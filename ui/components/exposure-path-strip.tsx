"use client";

import { Crosshair, KeyRound, Route, ShieldAlert, Wrench } from "lucide-react";
import { pathDisplayTitle, pathFixLabel, type ExposurePath } from "@/lib/exposure-path";

export function ExposurePathStrip({
  path,
  active = false,
  actionLabel,
  onAction,
}: {
  path: ExposurePath;
  active?: boolean;
  actionLabel?: string | undefined;
  onAction?: (() => void) | undefined;
}) {
  const fixLabel = pathFixLabel(path);

  return (
    <div className="flex flex-wrap items-center gap-3 border-b border-[var(--border-subtle)] bg-red-950/20 px-4 py-2.5 text-xs">
      <div className="flex min-w-0 flex-1 items-center gap-3">
        <span className="inline-flex items-center gap-1 rounded border border-red-500/40 bg-red-500/10 px-2 py-1 font-semibold uppercase text-red-200">
          <Crosshair className="h-3.5 w-3.5" />
          Top exposed path
        </span>
        <span className="rounded bg-red-500/15 px-2 py-0.5 font-mono text-[11px] uppercase text-red-200">
          {path.severity}
        </span>
        <span className="min-w-0 truncate text-[var(--text-secondary)]" title={path.label}>
          {pathDisplayTitle(path)}
        </span>
      </div>
      <div className="flex flex-wrap items-center gap-2 text-[11px] text-[var(--text-secondary)]">
        <Metric icon={ShieldAlert} label="risk" value={Math.round(path.riskScore * 10) / 10} />
        <Metric icon={Route} label="hops" value={Math.max(0, path.hops.length - 1)} />
        <Metric label="agents" value={path.affectedAgents.length} />
        {path.reachableTools.length > 0 && <Metric icon={Wrench} label="tools" value={path.reachableTools.length} />}
        {path.exposedCredentials.length > 0 && (
          <Metric icon={KeyRound} label="creds" value={path.exposedCredentials.length} />
        )}
        {fixLabel && (
          <span>
            fix <b className="text-emerald-300">{fixLabel}</b>
          </span>
        )}
        {onAction && actionLabel && (
          <button
            type="button"
            onClick={onAction}
            className="rounded border border-red-500/30 px-2 py-1 text-red-200 transition hover:border-red-400 hover:bg-red-500/10"
          >
            {active ? "Show all" : actionLabel}
          </button>
        )}
      </div>
    </div>
  );
}

function Metric({
  icon: Icon,
  label,
  value,
}: {
  icon?: typeof ShieldAlert | undefined;
  label: string;
  value: string | number;
}) {
  return (
    <span className="inline-flex items-center gap-1">
      {Icon && <Icon className="h-3 w-3" />}
      {label} <b className="text-foreground">{value}</b>
    </span>
  );
}
