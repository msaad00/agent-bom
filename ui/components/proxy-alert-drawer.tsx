"use client";

import { Drawer } from "@/components/drawer";
import { useDrawerWidth } from "@/lib/use-drawer-width";
import type { ProxyAlert } from "@/lib/api";
import { formatDate } from "@/lib/api";
import { proxyAlertDetailEntries, proxyAlertSummary } from "@/lib/proxy-alerts";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "border-red-300 bg-red-50 text-red-800 dark:border-red-800 dark:bg-red-950 dark:text-red-300",
  high: "border-orange-300 bg-orange-50 text-orange-800 dark:border-orange-800 dark:bg-orange-950 dark:text-orange-300",
  medium: "border-yellow-300 bg-yellow-50 text-yellow-800 dark:border-yellow-800 dark:bg-yellow-950 dark:text-yellow-300",
  low: "border-blue-300 bg-blue-50 text-blue-800 dark:border-blue-800 dark:bg-blue-950 dark:text-blue-300",
  info: "bg-[var(--surface-elevated)] text-[var(--text-secondary)] border-[var(--border-subtle)]",
};

export function ProxyAlertDrawer({
  alert,
  onClose,
}: {
  alert: ProxyAlert;
  onClose: () => void;
}) {
  const rows = proxyAlertDetailEntries(alert);
  const { width, onHandlePointerDown, onHandleKeyDown } = useDrawerWidth();

  return (
    <Drawer
      open
      onClose={onClose}
      size="none"
      panelStyle={{ width }}
      ariaLabel={`Proxy alert details for ${alert.tool_name}`}
      closeLabel="Close proxy alert drawer"
      backdropLabel="Dismiss proxy alert drawer"
      eyebrow="Runtime alert"
      title={alert.tool_name}
      subtitle={proxyAlertSummary(alert)}
      headerAside={
        <div className="flex flex-wrap items-center gap-2">
          <span
            className={`rounded border px-1.5 py-0.5 text-[10px] ${
              SEVERITY_COLORS[alert.severity] ?? SEVERITY_COLORS.info
            }`}
          >
            {alert.severity}
          </span>
          <span className="font-mono text-xs text-[var(--text-secondary)]">{alert.detector}</span>
        </div>
      }
      panelLeading={
        <div
          role="separator"
          aria-label="Resize drawer"
          aria-orientation="vertical"
          tabIndex={0}
          onKeyDown={onHandleKeyDown}
          onPointerDown={onHandlePointerDown}
          title="Drag to resize"
          className="absolute inset-y-0 left-0 z-10 w-1.5 cursor-col-resize bg-transparent transition-colors hover:bg-[color:var(--accent-border)] focus:bg-[color:var(--accent-border)] focus:outline-none"
        />
      }
    >
      {alert.ts ? (
        <p className="mb-4 text-xs text-[var(--text-tertiary)]">{formatDate(alert.ts)}</p>
      ) : null}
      <dl data-testid="proxy-alert-fields" className="grid grid-cols-2 gap-x-5 gap-y-3">
        {rows.map((row) => (
          <div key={`${row.label}:${row.value}`} className="min-w-0">
            <dt className="text-[10px] uppercase tracking-[0.16em] text-[var(--text-tertiary)]">
              {row.label}
            </dt>
            <dd className="mt-0.5 break-words font-mono text-xs text-[var(--foreground)]">{row.value}</dd>
          </div>
        ))}
      </dl>
    </Drawer>
  );
}
