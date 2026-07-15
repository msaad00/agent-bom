"use client";

import type { ReactNode } from "react";
import { MousePointerClick } from "lucide-react";

import { ICON_SIZE } from "@/lib/icon-sizes";

export type SplitLayoutProps = {
  /** Master pane — the list / index. Owns its own vertical scroll. */
  master: ReactNode;
  /** Detail pane — the selected record. Owns its own vertical scroll. */
  detail: ReactNode;
  /** Master pane width on md+ screens (e.g. "22rem", "30%"). */
  masterWidth?: string;
  /** Shown in the detail pane when `detail` is null/undefined. */
  placeholder?: ReactNode;
  /** Place the detail pane on the left instead of the right. */
  detailFirst?: boolean | undefined;
  /**
   * Container height. Panes scroll independently within it — the antidote to
   * long vertical pages. Defaults to the viewport minus the app shell chrome.
   */
  height?: string;
  className?: string | undefined;
  "data-testid"?: string | undefined;
};

/**
 * Master-detail split. List on one side, detail on the other, each pane with
 * its OWN internal scroll so the page never grows a single long column. Stacks
 * vertically on small screens. Token-styled for both themes.
 *
 * @example
 * ```tsx
 * <SplitLayout
 *   masterWidth="24rem"
 *   master={<DataTable rows={rows} onRowClick={setActive} selectedKey={active?.id} … />}
 *   detail={active ? <FindingDetail finding={active} /> : null}
 *   placeholder="Select a finding to see evidence and remediation."
 * />
 * ```
 */
export function SplitLayout({
  master,
  detail,
  masterWidth = "22rem",
  placeholder,
  detailFirst = false,
  height = "calc(100vh - 12rem)",
  className,
  "data-testid": testId,
}: SplitLayoutProps) {
  const masterPane = (
    <div
      className="min-h-0 min-w-0 shrink-0 overflow-y-auto md:basis-[var(--split-master-w)]"
      style={{ ["--split-master-w" as string]: masterWidth }}
    >
      {master}
    </div>
  );

  const detailPane = (
    <div className="min-h-0 min-w-0 flex-1 overflow-y-auto">
      {detail ?? (
        <div className="flex h-full min-h-[12rem] items-center justify-center rounded-xl border border-dashed border-[color:var(--border-subtle)] bg-[color:var(--surface-panel)] p-6 text-center">
          <div className="flex flex-col items-center gap-2 text-[color:var(--text-tertiary)]">
            <MousePointerClick className={ICON_SIZE.md} aria-hidden="true" />
            <p className="max-w-xs text-sm">
              {placeholder ?? "Select an item to see details."}
            </p>
          </div>
        </div>
      )}
    </div>
  );

  return (
    <div
      className={`flex min-h-0 flex-col gap-4 md:flex-row md:gap-5 ${
        detailFirst ? "md:flex-row-reverse" : ""
      } ${className ?? ""}`}
      style={{ height }}
      data-testid={testId}
    >
      {masterPane}
      {detailPane}
    </div>
  );
}
