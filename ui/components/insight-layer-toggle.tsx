"use client";

interface InsightLayerToggleProps {
  layers: { id: string; label: string; icon: string; active: boolean }[];
  onToggle: (id: string) => void;
}

export function InsightLayerToggle({ layers, onToggle }: InsightLayerToggleProps) {
  return (
    <div className="flex min-w-0 flex-wrap items-center gap-1">
      <span className="mr-1 whitespace-nowrap text-xs text-[color:var(--text-tertiary)]">Lens</span>
      {layers.map((layer) => (
        <button
          key={layer.id}
          onClick={() => onToggle(layer.id)}
          className={`flex max-w-full items-center gap-1 rounded-md border px-2 py-1 text-xs transition-colors ${
            layer.active
              ? "border-[color:var(--border-strong)] bg-[color:var(--surface-elevated)] text-[color:var(--foreground)]"
              : "border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] text-[color:var(--text-secondary)] hover:border-[color:var(--border-strong)] hover:text-[color:var(--foreground)]"
          }`}
        >
          <span>{layer.icon}</span>
          <span className="truncate">{layer.label}</span>
        </button>
      ))}
    </div>
  );
}
