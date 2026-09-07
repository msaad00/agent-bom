"use client";

import { SlidersHorizontal } from "lucide-react";
import { useRef, useState } from "react";

import { RankedPathList, type RankedPathRow } from "@/components/ranked-path-list";

const DETAIL_REGION_ID = "selected-investigation-path";

export function InvestigationFilterDrawer({ children }: { children: React.ReactNode }) {
  return (
    <details className="group rounded-xl border border-outline bg-surface-elevated/70">
      <summary className="flex cursor-pointer list-none items-center justify-between gap-3 px-3 py-2.5 text-xs font-medium text-foreground [&::-webkit-details-marker]:hidden">
        <span className="inline-flex items-center gap-2">
          <SlidersHorizontal className="h-3.5 w-3.5 text-ink-tertiary" aria-hidden="true" />
          Filters &amp; presets
        </span>
        <span className="text-[10px] uppercase tracking-[0.14em] text-ink-tertiary group-open:hidden">
          Show
        </span>
        <span className="hidden text-[10px] uppercase tracking-[0.14em] text-ink-tertiary group-open:inline">
          Hide
        </span>
      </summary>
      <div className="space-y-3 border-t border-outline p-3">{children}</div>
    </details>
  );
}

/**
 * Keeps the ranked queue and the selected path evidence in one working area.
 * Desktop operators can compare the bounded queue and detail side by side;
 * narrow viewports move to the newly selected detail rather than silently
 * updating content outside the visible area.
 */
export function InvestigationPathWorkspace({
  rows,
  selectedKey,
  onSelect,
  title,
  subtitle,
  filters,
  detail,
  queueFooter,
  sideRail,
}: {
  rows: RankedPathRow[];
  selectedKey: string | null;
  onSelect: (key: string) => void;
  title: string;
  subtitle: string;
  filters: React.ReactNode;
  detail: React.ReactNode;
  queueFooter?: React.ReactNode | undefined;
  sideRail?: React.ReactNode | undefined;
}) {
  const detailRef = useRef<HTMLDivElement>(null);
  const [announcement, setAnnouncement] = useState("");

  function handleSelect(key: string) {
    const row = rows.find((candidate) => candidate.selectionKey === key);
    onSelect(key);
    if (row) {
      setAnnouncement(`Focused path ${row.rank}: ${row.cve ? `${row.cve} · ` : ""}${row.title}`);
    }
    if (window.matchMedia?.("(max-width: 1279px)").matches) {
      window.requestAnimationFrame(() => {
        detailRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
      });
    }
  }

  function handleQueueKeyDown(event: React.KeyboardEvent<HTMLDivElement>) {
    if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") return;
    event.preventDefault();
    if (rows.length === 0) return;
    const currentIndex = rows.findIndex((row) => row.selectionKey === selectedKey);
    const direction = event.key === "ArrowRight" ? 1 : -1;
    const nextIndex =
      currentIndex < 0 ? 0 : (currentIndex + direction + rows.length) % rows.length;
    handleSelect(rows[nextIndex]!.selectionKey);
  }

  return (
    <section
      aria-label="Investigation workspace"
      data-layout={rows.length === 1 ? "focused-path" : "responsive-split"}
      className={rows.length === 1 ? "grid gap-4" : "grid gap-4 xl:grid-cols-[minmax(20rem,24rem)_minmax(0,1fr)] xl:items-start"}
    >
      <details open={rows.length !== 1} className="investigation-queue rounded-xl border border-outline bg-surface p-4">
        <summary className="cursor-pointer text-sm font-medium text-foreground">{rows.length === 1 ? "1 path selected · change focus or filters" : `${rows.length} paths · investigation queue`}</summary>
        <div className="mt-3">
          <div>
            <h2 className="text-base font-semibold text-foreground">{title}</h2>
            <p className="mt-1 text-xs text-ink-tertiary">{subtitle}</p>
          </div>

          <a href={`#${DETAIL_REGION_ID}`} className="mt-3 flex min-h-11 items-center text-sm font-medium text-foreground xl:hidden">View selected path</a>
          <div className="mt-3">
            <InvestigationFilterDrawer>{filters}</InvestigationFilterDrawer>
          </div>

          <RankedPathList
            rows={rows}
            selectedKey={selectedKey}
            onSelect={handleSelect}
            onKeyDown={handleQueueKeyDown}
            controlsId={DETAIL_REGION_ID}
          />
          {queueFooter}
          {sideRail ? <div className="mt-4">{sideRail}</div> : null}
        </div>
      </details>

      <div
        ref={detailRef}
        id={DETAIL_REGION_ID}
        role="region"
        aria-label="Selected path detail"
        tabIndex={-1}
        className="min-w-0 scroll-mt-24 xl:sticky xl:top-20"
      >
        {detail}
      </div>
      <p role="status" aria-live="polite" aria-atomic="true" className="sr-only">
        {announcement}
      </p>
    </section>
  );
}
