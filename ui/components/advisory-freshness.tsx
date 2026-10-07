"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { api, type IntelSource } from "@/lib/api";

/** Feed sync receipts describe advisory data, independently of scan timestamps. */
export function AdvisoryFreshness() {
  const [sources, setSources] = useState<IntelSource[] | null>(null);
  const [unavailable, setUnavailable] = useState(false);
  useEffect(() => {
    let active = true;
    async function load() {
      try {
        const result = await api.getIntelSources();
        if (active) setSources(result.sources.filter(source => source.enabled));
      } catch {
        if (active) setUnavailable(true);
      }
    }
    void load();
    return () => { active = false; };
  }, []);
  return <details className="rounded-lg border border-outline bg-surface px-3 py-2 text-xs" aria-label="Advisory data freshness">
    <summary className="cursor-pointer font-medium text-foreground">Advisory data · {unavailable ? "source status unavailable" : sources === null ? "loading source receipts" : `${sources.length} enabled sources`}</summary>
    <p className="mt-2 text-ink-secondary">Last recorded feed sync and recorded status are separate from the scan time. Missing timestamps remain unknown.</p>
    {sources?.length ? <ul className="mt-2 space-y-2">{sources.map(source => <li key={source.source_id}>
      <span className="font-medium">{source.display_name}</span> · {source.feed_run?.status || "status unknown"} · Last sync: {source.feed_run?.last_synced || "unknown"}
      {source.feed_run?.cap_hit && <span> · partial feed</span>}
      {!!source.feed_run?.validation_failures && <span> · validation failures recorded</span>}
    </li>)}</ul> : sources && <p className="mt-2">No enabled source receipts were returned. This does not establish current advisory coverage.</p>}
    <Link href="/integrations?tab=intel" className="mt-2 inline-block py-2 underline">Inspect advisory sources</Link>
  </details>;
}
