"use client";

import {
  useId,
  useState,
  type CSSProperties,
  type ElementType,
  type ReactNode,
} from "react";
import { ChevronDown, ChevronRight } from "lucide-react";

import { ICON_SIZE } from "@/lib/icon-sizes";

type CollapsibleProps = {
  /** Header label. */
  title: ReactNode;
  /** Optional secondary line under the title. */
  subtitle?: ReactNode | undefined;
  /** Optional count rendered as a pill next to the title. */
  count?: number | undefined;
  /** Optional leading icon (e.g. a Lucide component) for the header. */
  icon?: ElementType | undefined;
  /** Whether the panel starts open. Defaults to true. */
  defaultOpen?: boolean | undefined;
  /**
   * Override the header title classes. Lets a section opt into a larger,
   * normal-case heading (e.g. Overview section headers) instead of the default
   * tiny uppercase `bare` label or `text-sm` boxed label.
   */
  titleClassName?: string | undefined;
  /** Optional trailing content rendered on the right of the header. */
  actions?: ReactNode;
  /**
   * Nested / in-card mode: no outer border or fill — use inside a parent
   * surface (e.g. Overview command center).
   */
  bare?: boolean | undefined;
  /**
   * Cap body height and scroll inside the panel (e.g. `"16rem"`). Long lists
   * stay in-window instead of stretching the page.
   */
  scrollMaxHeight?: string | undefined;
  /** Extra classes for the outer wrapper. */
  className?: string | undefined;
  /** Extra classes for the body panel. */
  bodyClassName?: string | undefined;
  children: ReactNode;
  "data-testid"?: string | undefined;
};

/**
 * Progressive-disclosure panel: header toggles body with `aria-expanded`.
 * Supports nested (`bare`) placement and in-panel scrolling for dense consoles.
 */
export function Collapsible({
  title,
  subtitle,
  count,
  icon: Icon,
  defaultOpen = true,
  actions,
  bare = false,
  scrollMaxHeight,
  className,
  bodyClassName,
  titleClassName,
  children,
  "data-testid": testId,
}: CollapsibleProps) {
  const [open, setOpen] = useState(defaultOpen);
  const panelId = useId();
  const Chevron = open ? ChevronDown : ChevronRight;
  const resolvedTitleClass =
    titleClassName ??
    (bare
      ? "text-[10px] uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]"
      : "text-sm");

  const scrollStyle: CSSProperties | undefined = scrollMaxHeight
    ? { maxHeight: scrollMaxHeight, overflowY: "auto" }
    : undefined;

  return (
    <div
      className={
        bare
          ? `${className ?? ""}`
          : `rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] ${className ?? ""}`
      }
      data-testid={testId}
    >
      <div className={`flex items-center gap-2 ${bare ? "px-0 py-2.5" : "px-4 py-3"}`}>
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
          <span className="min-w-0 flex-1">
            <span className="flex min-w-0 items-center gap-2">
              <span
                className={`truncate font-semibold text-[color:var(--foreground)] ${resolvedTitleClass}`}
              >
                {title}
              </span>
              {typeof count === "number" ? (
                <span className="shrink-0 rounded-full border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-2 py-0.5 text-[11px] font-medium tabular-nums text-[color:var(--text-secondary)]">
                  {count}
                </span>
              ) : null}
            </span>
            {subtitle ? (
              <span className="mt-0.5 block truncate text-xs font-normal normal-case tracking-normal text-[color:var(--text-secondary)]">
                {subtitle}
              </span>
            ) : null}
          </span>
        </button>
        {actions ? <div className="shrink-0">{actions}</div> : null}
      </div>
      <div
        id={panelId}
        hidden={!open}
        className={`${bare ? "pb-1" : "px-4 pb-4"} ${bodyClassName ?? ""}`}
        style={scrollStyle}
      >
        {children}
      </div>
    </div>
  );
}
