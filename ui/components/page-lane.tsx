import type { ReactNode } from "react";
import { PAGE_LANE_META, type PageLane } from "@/lib/page-lanes";

export function PageScopeChip({ lane }: { lane: PageLane }) {
  const meta = PAGE_LANE_META[lane];
  return (
    <span
      className="inline-flex items-center rounded-full border px-2.5 py-0.5 text-[11px] font-medium"
      style={{
        borderColor: `${meta.accent}55`,
        backgroundColor: `${meta.accent}14`,
        color: meta.accent,
      }}
    >
      {meta.scope}
    </span>
  );
}

export function PageLaneHeader({
  lane,
  title,
  subtitle,
  actions,
  banner,
}: {
  lane: PageLane;
  title: string;
  subtitle?: string;
  actions?: ReactNode;
  banner?: ReactNode;
}) {
  const meta = PAGE_LANE_META[lane];
  return (
    <div className="space-y-3">
      <header className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <p
              className="text-[11px] font-semibold uppercase tracking-[0.16em]"
              style={{ color: meta.accent }}
            >
              {meta.label}
            </p>
            <PageScopeChip lane={lane} />
          </div>
          <h1 className="mt-1 text-2xl font-semibold tracking-tight text-[color:var(--foreground)]">
            {title}
          </h1>
          {subtitle ? (
            <p className="mt-1 max-w-2xl text-sm text-[color:var(--text-secondary)]">{subtitle}</p>
          ) : null}
        </div>
        {actions ? (
          <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div>
        ) : null}
      </header>
      {banner}
    </div>
  );
}

export function CatalogBanner() {
  return (
    <div className="rounded-lg border border-amber-500/25 bg-amber-500/10 px-3 py-2 text-xs leading-5 text-amber-100/90">
      <span className="font-medium text-amber-50">Reference catalog only.</span>{" "}
      Capability risk scores what an MCP server can do (filesystem, SQL, cloud APIs) — not CVE patch status or your live estate.
      Use <span className="font-medium text-amber-50">Agent BOM</span> and <span className="font-medium text-amber-50">Findings</span> for tenant inventory and vulnerabilities.
    </div>
  );
}
