/**
 * Opt-in "I have a report file, let me in" mode.
 *
 * `ApiOfflineState` can import a scan report entirely in the browser — read the
 * file, validate it, render it — with no backend involved. It is mounted by
 * `app/page.tsx`, which sits inside `AuthGate`, so every auth-probe failure
 * (401 redirect, unreachable control plane, unexpected error) replaced it.
 * The one feature designed for "no working backend" was unreachable in exactly
 * that situation.
 *
 * This flag is what the user sets by pressing "Continue offline with a report
 * file". It is deliberately narrow:
 *
 *  - it is never on by default, so the gate still blocks by default;
 *  - it grants no data — every API call behind it fails exactly as it would
 *    have, and only a file the user supplies is ever rendered;
 *  - it lives in `sessionStorage`, so it dies with the tab rather than
 *    quietly weakening the shell of every future visit.
 *
 * Mirrors the `theme-mode` store so components re-render when it changes.
 */

import { useSyncExternalStore } from "react";

const OFFLINE_STORAGE_KEY = "agent-bom-offline-report";
const OFFLINE_CHANGE_EVENT = "agent-bom-offline-report-change";

export function isOfflineReportMode(): boolean {
  if (typeof window === "undefined") return false;
  try {
    return window.sessionStorage.getItem(OFFLINE_STORAGE_KEY) === "1";
  } catch {
    return false;
  }
}

function setOfflineReportMode(enabled: boolean): void {
  if (typeof window === "undefined") return;
  try {
    if (enabled) window.sessionStorage.setItem(OFFLINE_STORAGE_KEY, "1");
    else window.sessionStorage.removeItem(OFFLINE_STORAGE_KEY);
  } catch {
    // A blocked storage still gets the event; the mode just will not persist
    // across a reload, which is a better failure than throwing at the user.
  }
  window.dispatchEvent(new Event(OFFLINE_CHANGE_EVENT));
}

export function enableOfflineReportMode(): void {
  setOfflineReportMode(true);
}

export function disableOfflineReportMode(): void {
  setOfflineReportMode(false);
}

export function subscribeOfflineReportMode(onChange: () => void): () => void {
  if (typeof window === "undefined") return () => {};
  const handleChange = () => onChange();
  window.addEventListener("storage", handleChange);
  window.addEventListener(OFFLINE_CHANGE_EVENT, handleChange);
  return () => {
    window.removeEventListener("storage", handleChange);
    window.removeEventListener(OFFLINE_CHANGE_EVENT, handleChange);
  };
}

export function useOfflineReportMode(): boolean {
  return useSyncExternalStore(
    subscribeOfflineReportMode,
    isOfflineReportMode,
    () => false,
  );
}
