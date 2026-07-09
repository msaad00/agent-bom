import Link from "next/link";
import type { ServiceEntry, ServiceId } from "@/lib/api-types";
import {
  SERVICE_META,
  serviceRequiresLabel,
  serviceStateLabel,
} from "@/lib/service-registry";

const STATE_STYLE: Record<ServiceEntry["state"], string> = {
  locked: "border-zinc-700 bg-zinc-900/80 text-zinc-400",
  connected: "border-amber-500/30 bg-amber-500/10 text-amber-200",
  live: "border-emerald-500/30 bg-emerald-500/10 text-emerald-200",
};

export function ServiceStateChip({
  serviceId,
  entry,
  registry,
  showUnlock = true,
}: {
  serviceId: ServiceId;
  entry: ServiceEntry;
  registry?: Partial<Record<ServiceId, ServiceEntry>> | undefined;
  showUnlock?: boolean;
}) {
  const meta = SERVICE_META[serviceId];
  const requires = serviceRequiresLabel(registry, serviceId);

  return (
    <div className="flex flex-wrap items-center gap-2">
      <span
        className={`inline-flex items-center rounded-full border px-2.5 py-0.5 text-[11px] font-medium ${STATE_STYLE[entry.state]}`}
      >
        {serviceStateLabel(entry.state)}
        {entry.count > 0 ? ` · ${entry.count}` : ""}
      </span>
      {requires && entry.state === "locked" ? (
        <span className="text-[11px] text-[color:var(--text-tertiary)]">
          Requires {requires}
        </span>
      ) : null}
      {showUnlock && entry.state !== "live" ? (
        <Link
          href={meta.unlockHref}
          className="text-[11px] font-medium text-emerald-400 hover:text-emerald-300"
        >
          {meta.unlockLabel}
        </Link>
      ) : null}
    </div>
  );
}

export function ServiceStateBanner({
  serviceId,
  entry,
  registry,
}: {
  serviceId: ServiceId;
  entry: ServiceEntry;
  registry?: Partial<Record<ServiceId, ServiceEntry>> | undefined;
}) {
  if (entry.state === "live") {
    return null;
  }
  const meta = SERVICE_META[serviceId];
  const requires = serviceRequiresLabel(registry, serviceId);
  return (
    <div className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2 text-xs text-[color:var(--text-secondary)]">
      <span className="font-medium text-[color:var(--foreground)]">{meta.label}</span> is{" "}
      {entry.state === "locked" ? "not configured yet" : "connected but waiting for first evidence"}.
      {requires ? ` Requires ${requires}.` : null}{" "}
      <Link href={meta.unlockHref} className="font-medium text-emerald-400 hover:text-emerald-300">
        {meta.unlockLabel}
      </Link>
    </div>
  );
}
