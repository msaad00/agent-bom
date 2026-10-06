"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import type { AssetRow } from "@/lib/inventory";

/** Keep the selected identity when following an evidence link and returning. */
export function useInventorySelection(rows: AssetRow[], scope: string | undefined, load: (id: string) => Promise<void>) {
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const loaded = useRef("");
  useEffect(() => {
    const restore = () => setSelectedId(new URLSearchParams(window.location.search).get("asset"));
    restore();
    window.addEventListener("popstate", restore);
    return () => window.removeEventListener("popstate", restore);
  }, []);
  const selected = rows.find(row => row.id === selectedId) ?? null;
  useEffect(() => {
    if (!selected || !scope) { loaded.current = ""; return; }
    const key = JSON.stringify([scope, selected.id]);
    if (loaded.current === key) return;
    loaded.current = key;
    void load(selected.id);
  }, [selected, scope, load]);
  const select = useCallback((id: string | null) => {
    setSelectedId(id);
    const url = new URL(window.location.href);
    if (id) url.searchParams.set("asset", id);
    else url.searchParams.delete("asset");
    window.history.replaceState(window.history.state, "", url);
  }, []);
  return { selected, select };
}
