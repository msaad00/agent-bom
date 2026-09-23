"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import type { ContextGraphData } from "@/lib/context-graph";

/** Keep responses and errors attached to the scan and agent that requested them. */
export function useContextGraph(jobId: string, agent: string | null) {
  const scope = JSON.stringify([jobId, agent]);
  const [result, setResult] = useState<{
    scope: string;
    data: ContextGraphData | null;
    error: string | null;
  } | null>(null);

  useEffect(() => {
    let cancelled = false;
    if (!jobId) return;
    api.getContextGraph(jobId, agent ?? undefined).then(
      (data) => {
        if (!cancelled) setResult({ scope, data: data as unknown as ContextGraphData, error: null });
      },
      () => {
        if (!cancelled) setResult({ scope, data: null, error: "Unable to load context evidence for this scan and agent." });
      },
    );
    return () => { cancelled = true; };
  }, [jobId, agent, scope]);

  return result?.scope === scope ? result : { data: null, error: null };
}
