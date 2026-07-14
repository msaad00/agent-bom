"use client";

import { useEffect, useState, type ReactNode } from "react";
import { ChevronLeft, X } from "lucide-react";

export type DrawerSize = "sm" | "md" | "lg" | "xl" | "2xl" | "3xl" | "4xl" | "5xl";

const SIZE_CLASS: Record<DrawerSize, string> = {
  sm: "max-w-sm",
  md: "max-w-md",
  lg: "max-w-lg",
  xl: "max-w-xl",
  "2xl": "max-w-2xl",
  "3xl": "max-w-3xl",
  "4xl": "max-w-4xl",
  "5xl": "max-w-5xl",
};

export interface DrawerProps {
  open: boolean;
  onClose: () => void;
  /** When set, renders a back affordance in the header (e.g. drill-down → parent). */
  onBack?: (() => void) | undefined;
  title: ReactNode;
  subtitle?: ReactNode;
  /** Small uppercase label above the title (framework, provider, kind…). */
  eyebrow?: ReactNode;
  /** Optional trailing header content (status pill, etc.). */
  headerAside?: ReactNode;
  /** Sticky footer action row. */
  footer?: ReactNode;
  size?: DrawerSize;
  ariaLabel?: string;
  children: ReactNode;
}

/**
 * Shared right-anchored slide-over. Token-themed, Esc-to-close, backdrop-close,
 * optional back button so drill-downs never dead-end. Caller owns open state.
 */
export function Drawer({
  open,
  onClose,
  onBack,
  title,
  subtitle,
  eyebrow,
  headerAside,
  footer,
  size = "xl",
  ariaLabel,
  children,
}: DrawerProps) {
  const [entered, setEntered] = useState(false);

  useEffect(() => {
    if (!open) {
      setEntered(false);
      return;
    }
    const raf = requestAnimationFrame(() => setEntered(true));
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    return () => {
      cancelAnimationFrame(raf);
      document.removeEventListener("keydown", onKey);
    };
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div
      className={`fixed inset-0 z-[80] flex justify-end bg-black/45 backdrop-blur-sm transition-opacity duration-200 ${
        entered ? "opacity-100" : "opacity-0"
      }`}
      role="dialog"
      aria-modal="true"
      aria-label={ariaLabel ?? (typeof title === "string" ? title : "Details")}
    >
      <button
        type="button"
        className="absolute inset-0 cursor-default"
        aria-label="Close"
        onClick={onClose}
      />
      <aside
        className={`relative flex h-full w-full flex-col border-l border-[color:var(--border-subtle)] bg-[color:var(--surface)] shadow-2xl transition-transform duration-200 ease-out ${
          SIZE_CLASS[size]
        } ${entered ? "translate-x-0" : "translate-x-full"}`}
      >
        <div className="flex items-start justify-between gap-4 border-b border-[color:var(--border-subtle)] p-5">
          <div className="flex min-w-0 items-start gap-2">
            {onBack ? (
              <button
                type="button"
                onClick={onBack}
                className="mt-0.5 shrink-0 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-1.5 text-[color:var(--text-secondary)] transition-colors hover:text-[color:var(--foreground)]"
                aria-label="Back"
              >
                <ChevronLeft className="h-4 w-4" />
              </button>
            ) : null}
            <div className="min-w-0">
              {eyebrow ? (
                <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">
                  {eyebrow}
                </p>
              ) : null}
              <h2 className="mt-1 truncate text-base font-semibold leading-snug text-[color:var(--foreground)]">
                {title}
              </h2>
              {subtitle ? (
                <p className="mt-1 text-sm text-[color:var(--text-secondary)]">{subtitle}</p>
              ) : null}
            </div>
          </div>
          <div className="flex shrink-0 items-center gap-2">
            {headerAside}
            <button
              type="button"
              onClick={onClose}
              className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-2 text-[color:var(--text-secondary)] transition-colors hover:text-[color:var(--foreground)]"
              aria-label="Close"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto p-5">{children}</div>

        {footer ? (
          <div className="border-t border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-4">
            {footer}
          </div>
        ) : null}
      </aside>
    </div>
  );
}
