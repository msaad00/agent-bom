"use client";

import type { ComponentType, ReactNode } from "react";

type Chip<T extends string> = { id: T; label: string; count: number };

/** Shared presentation only; each lens owns its evidence classification. */
export function GraphLensLegend<T extends string>({
  id, title, icon: Icon, tone, active, onToggleActive, filter, onFilterChange,
  chips, inactiveContent, children, switchToggle = false, groupLabel,
}: {
  id: string;
  title: string;
  icon: ComponentType<{ className?: string }>;
  tone: "sky" | "violet";
  active: boolean;
  onToggleActive: (next: boolean) => void;
  filter: T;
  onFilterChange: (filter: T) => void;
  chips: Chip<T>[];
  inactiveContent: ReactNode;
  children?: ReactNode;
  switchToggle?: boolean;
  groupLabel?: string;
}) {
  const inactive = "border-outline bg-surface/60 text-ink-secondary hover:text-foreground";
  const selected = tone === "sky"
    ? "border-sky-500/60 bg-sky-500/15 text-sky-800 dark:text-sky-100"
    : "border-violet-500/60 bg-violet-500/15 text-violet-800 dark:text-violet-100";
  const iconColor = tone === "sky" ? "text-sky-700 dark:text-sky-400" : "text-violet-700 dark:text-violet-400";
  return (
    <div data-testid={`${id}-legend`} className="mt-3 rounded-2xl border border-outline bg-background/70 p-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <Icon className={`h-4 w-4 ${iconColor}`} />
          <span className={`text-[10px] uppercase tracking-[0.24em] ${iconColor}`}>{title}</span>
        </div>
        <button type="button" data-testid={`${id}-toggle`}
          role={switchToggle ? "switch" : undefined}
          aria-checked={switchToggle ? active : undefined}
          aria-pressed={switchToggle ? undefined : active}
          onClick={() => onToggleActive(!active)}
          className={`rounded-full border px-3 py-1 text-xs ${switchToggle ? "font-medium " : ""}transition-colors ${active ? switchToggle ? "border-sky-500/60 bg-sky-500/15 text-sky-700 dark:text-sky-200" : selected : inactive}`}>
          {active ? "Lens on" : "Lens off"}
        </button>
      </div>
      {active ? <>
        <div className="mt-3 flex flex-wrap gap-2" data-testid={`${id}-chips`}
          role={groupLabel ? "group" : undefined} aria-label={groupLabel}>
          {chips.map(chip => <button key={chip.id} type="button" aria-pressed={filter === chip.id}
            data-testid={`${id}-chip-${chip.id}`} onClick={() => onFilterChange(chip.id)}
            className={`rounded-full border px-3 py-1 text-xs transition-colors ${filter === chip.id ? selected : inactive}`}>
            {chip.label}
            <span className="ml-1.5 font-mono text-[11px] text-ink-tertiary">{chip.count}</span>
          </button>)}
        </div>
        {children}
      </> : <p className="mt-2 text-xs text-ink-tertiary">{inactiveContent}</p>}
    </div>
  );
}
