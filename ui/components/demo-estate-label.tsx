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
      className="pointer-events-none fixed bottom-4 right-4 z-[120] rounded-full border border-emerald-500/35 bg-zinc-950/90 px-3 py-1.5 font-mono text-[11px] font-semibold uppercase tracking-[0.12em] text-emerald-200/95 shadow-lg shadow-black/30"
      aria-hidden="true"
    >
      Demo data — simulated estate
    </div>
  );
}
