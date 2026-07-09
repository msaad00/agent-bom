"use client";

import { useCaptureMode } from "@/lib/use-capture-mode";
import { useDeploymentContext } from "@/hooks/use-deployment-context";

function hasDemoSeedSources(scanSources: string[] | undefined): boolean {
  if (!scanSources?.length) return false;
  return scanSources.some((source) => source.includes("demo"));
}

export function DemoEstateLabel() {
  const captureMode = useCaptureMode();
  const { counts } = useDeploymentContext();
  const visible = captureMode || hasDemoSeedSources(counts?.scan_sources);

  if (!visible) return null;

  return (
    <div
      id="demo-estate-watermark"
      className={`pointer-events-none fixed z-[120] max-w-[min(18rem,calc(100vw-1.5rem))] truncate rounded-full border border-emerald-500/40 bg-[color:var(--surface-elevated)]/95 px-3 py-1 font-medium uppercase tracking-[0.1em] text-emerald-200 shadow-md shadow-black/20 right-3 top-16 lg:right-5 lg:top-3 ${
        captureMode ? "text-[11px]" : "text-xs"
      }`}
      aria-hidden="true"
    >
      Demo data — simulated estate
    </div>
  );
}
