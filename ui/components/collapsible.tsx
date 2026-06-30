"use client";

import {
  useId,
  useState,
  type ElementType,
  type ReactNode,
} from "react";
import { ChevronDown, ChevronRight } from "lucide-react";

import { ICON_SIZE } from "@/lib/icon-sizes";

type CollapsibleProps = {
  /** Header label. */
  title: ReactNode;
  /** Optional count rendered as a pill next to the title. */
  count?: number | undefined;
  /** Optional leading icon (e.g. a Lucide component) for the header. */
  icon?: ElementType | undefined;
  /** Whether the panel starts open. Defaults to true. */
  defaultOpen?: boolean | undefined;
  /** Optional trailing content rendered on the right of the header. */
  actions?: ReactNode;
  /** Extra classes for the outer wrapper. */
  className?: string | undefined;
  /** Extra classes for the body panel. */
  bodyClassName?: string | undefined;
  children: ReactNode;
  "data-testid"?: string | undefined;
};

/**
 * Standard progressive-disclosure primitive. A header `<button>` toggles a
 * panel; the chevron rotates ChevronRight → ChevronDown and the button carries
 * `aria-expanded` + `aria-controls` wired to the panel `id`. This replaces the
 * hand-rolled collapse logic scattered across scan-result / nav / graph-chrome
 * and gives the many never-collapsible sections a one-line way to fold.
 */
export function Collapsible({
  title,
  count,
  icon: Icon,
  defaultOpen = true,
  actions,
  className,
  bodyClassName,
  children,
  "data-testid": testId,
}: CollapsibleProps) {
  const [open, setOpen] = useState(defaultOpen);
  const panelId = useId();
  const Chevron = open ? ChevronDown : ChevronRight;

  return (
    <div
      className={`rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] ${className ?? ""}`}
      data-testid={testId}
    >
      <div className="flex items-center gap-2 px-4 py-3">
        <button
          type="button"
          onClick={() => setOpen((v) => !v)}
          aria-expanded={open}
          aria-controls={panelId}
          className="flex min-w-0 flex-1 items-center gap-2 text-left"
        >
          <Chevron
            className={`${ICON_SIZE.sm} shrink-0 text-[color:var(--text-tertiary)] transition-transform`}
            aria-hidden="true"
          />
          {Icon ? (
            <Icon
              className={`${ICON_SIZE.sm} shrink-0 text-[color:var(--text-secondary)]`}
              aria-hidden="true"
            />
          ) : null}
          <span className="truncate text-sm font-semibold text-[color:var(--foreground)]">
            {title}
          </span>
          {typeof count === "number" ? (
            <span className="ml-1 rounded-full border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-2 py-0.5 text-[11px] font-medium tabular-nums text-[color:var(--text-secondary)]">
              {count}
            </span>
          ) : null}
        </button>
        {actions ? <div className="shrink-0">{actions}</div> : null}
      </div>
      <div id={panelId} hidden={!open} className={`px-4 pb-4 ${bodyClassName ?? ""}`}>
        {children}
      </div>
    </div>
  );
}
