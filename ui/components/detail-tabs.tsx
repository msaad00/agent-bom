"use client";

import { useRef } from "react";

export interface DetailTab<T extends string> {
  key: T;
  label: string;
  badge?: string | undefined;
}

export function DetailTabs<T extends string>({
  tabs,
  value,
  onChange,
  ariaLabel,
}: {
  tabs: readonly DetailTab<T>[];
  value: T;
  onChange: (value: T) => void;
  ariaLabel: string;
}) {
  const tabButtons = useRef<Array<HTMLButtonElement | null>>([]);
  return (
    <div
      className="mb-4 flex flex-wrap gap-1 border-b border-outline"
      role="tablist"
      aria-label={ariaLabel}
    >
      {tabs.map((entry, index) => {
        const active = value === entry.key;
        return (
          <button
            key={entry.key}
            ref={(button) => { tabButtons.current[index] = button; }}
            type="button"
            role="tab"
            aria-selected={active}
            tabIndex={active ? 0 : -1}
            onClick={() => onChange(entry.key)}
            onKeyDown={(event) => {
              const nextIndex = event.key === "ArrowRight" ? (index + 1) % tabs.length
                : event.key === "ArrowLeft" ? (index - 1 + tabs.length) % tabs.length
                  : event.key === "Home" ? 0
                    : event.key === "End" ? tabs.length - 1 : null;
              if (nextIndex === null) return;
              const next = tabs[nextIndex];
              if (!next) return;
              event.preventDefault();
              onChange(next.key);
              tabButtons.current[nextIndex]?.focus();
            }}
            className={`-mb-px border-b-2 px-3 py-2 text-sm font-medium transition-colors ${
              active
                ? "border-emerald-500 text-foreground"
                : "border-transparent text-ink-tertiary hover:text-ink-secondary"
            }`}
          >
            {entry.label}
            {entry.badge ? (
              <span className="ml-1.5 rounded-full bg-surface-muted px-1.5 py-0.5 text-[10px] text-ink-secondary">
                {entry.badge}
              </span>
            ) : null}
          </button>
        );
      })}
    </div>
  );
}
