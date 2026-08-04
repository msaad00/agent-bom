"use client";

import Link from "next/link";

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
    <Link
      href="/demo-estate"
      id="demo-estate-watermark"
      className={`z-[120] max-w-[min(18rem,calc(100vw-1.5rem))] truncate rounded-full border border-emerald-500/40 bg-[color:var(--surface-elevated)]/95 px-3 py-1 font-medium uppercase tracking-[0.1em] text-emerald-700 shadow-md shadow-black/20 transition hover:border-emerald-500/70 hover:text-emerald-800 dark:text-emerald-200 dark:hover:text-emerald-100 ${
        captureMode
          ? "fixed right-5 top-16 text-[11px]"
          : "absolute left-4 top-16 text-[10px] sm:fixed sm:bottom-4 sm:left-auto sm:right-4 sm:top-auto sm:text-[11px]"
      }`}
      aria-label="Open the synthetic enterprise demo story"
    >
      Demo data — sample environment
    </Link>
  );
}
