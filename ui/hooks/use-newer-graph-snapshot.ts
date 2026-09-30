"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "@/lib/api";
import { ApiError } from "@/lib/api-errors";
import type { GraphSnapshot } from "@/lib/api-types";

export function newerGraphSnapshot(items: GraphSnapshot[], scanId: string): GraphSnapshot | null {
  const current = items.find(item => item.scan_id === scanId);
  if (!current || !Number.isFinite(Date.parse(current.created_at))) return null;
  return items.filter(item => item.scan_id !== scanId && item.snapshot_kind === current.snapshot_kind
    && Date.parse(item.created_at) > Date.parse(current.created_at))
    .sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at))[0] ?? null;
}

/** Read only bounded snapshot metadata; never mutate the graph or its viewport. */
export function useNewerGraphSnapshot(scanId: string, owner: string, enabled: boolean) {
  const scope = JSON.stringify([scanId, owner]);
  const [state, setState] = useState<{ scope: string; newer: GraphSnapshot | null; error: boolean; checked: boolean; checking: boolean }>({ scope, newer: null, error: false, checked: false, checking: false });
  const active = useRef<AbortController | null>(null);
  const denied = useRef(false);
  const refresh = useCallback(async (manual = false) => {
    if (manual) denied.current = false;
    if (!enabled || !scanId || active.current || denied.current) return;
    const controller = new AbortController(); active.current = controller;
    setState(previous => previous.scope === scope ? { ...previous, checking: true } : { scope, newer: null, error: false, checked: false, checking: true });
    try {
      const items = await api.getGraphSnapshots(40, 0, { signal: controller.signal });
      if (controller.signal.aborted) return;
      const known = items.some(item => item.scan_id === scanId && Number.isFinite(Date.parse(item.created_at)));
      setState({ scope, newer: newerGraphSnapshot(items, scanId), error: !known, checked: true, checking: false });
    } catch (error) {
      if (controller.signal.aborted) return;
      denied.current = error instanceof ApiError && (error.status === 401 || error.status === 403);
      setState({ scope, newer: null, error: true, checked: false, checking: false });
    } finally { if (active.current === controller) active.current = null; }
  }, [enabled, scanId, scope]);
  useEffect(() => {
    denied.current = false;
    const checkVisible = () => { if (document.visibilityState !== "hidden") void refresh(); };
    checkVisible();
    const timer = window.setInterval(checkVisible, 30_000);
    document.addEventListener("visibilitychange", checkVisible);
    return () => { window.clearInterval(timer); document.removeEventListener("visibilitychange", checkVisible); active.current?.abort(); active.current = null; };
  }, [refresh]);
  return { ...(state.scope === scope ? state : { newer: null, error: false, checked: false, checking: false }), refresh };
}
