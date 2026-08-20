"use client";

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
  return (
    <div
      className="mb-4 flex flex-wrap gap-1 border-b border-[color:var(--border-subtle)]"
      role="tablist"
      aria-label={ariaLabel}
    >
      {tabs.map((entry) => {
        const active = value === entry.key;
        return (
          <button
            key={entry.key}
            type="button"
            role="tab"
            aria-selected={active}
            tabIndex={active ? 0 : -1}
            onClick={() => onChange(entry.key)}
            className={`-mb-px border-b-2 px-3 py-2 text-sm font-medium transition-colors ${
              active
                ? "border-emerald-500 text-[color:var(--foreground)]"
                : "border-transparent text-[color:var(--text-tertiary)] hover:text-[color:var(--text-secondary)]"
            }`}
          >
            {entry.label}
            {entry.badge ? (
              <span className="ml-1.5 rounded-full bg-[color:var(--surface-muted)] px-1.5 py-0.5 text-[10px] text-[color:var(--text-secondary)]">
                {entry.badge}
              </span>
            ) : null}
          </button>
        );
      })}
    </div>
  );
}
