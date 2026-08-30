"use client";

import { useEffect, useState } from "react";

export function isCaptureModeSearch(search: string): boolean {
  return new URLSearchParams(search).get("capture") === "1";
}

export function isReferenceEvidenceLabSearch(search: string): boolean {
  const params = new URLSearchParams(search);
  return (
    params.get("capture") === "1" &&
    params.get("scan") === "reference-evidence-correlation-v1"
  );
}

function readLocationSearch(predicate: (search: string) => boolean): boolean {
  if (typeof window === "undefined") return false;
  return predicate(window.location.search);
}

function useLocationSearch(predicate: (search: string) => boolean): boolean {
  // Defer URL reads until after mount so SSR and the first client paint match.
  const [matches, setMatches] = useState(false);

  useEffect(() => {
    const update = () => setMatches(readLocationSearch(predicate));
    update();
    window.addEventListener("popstate", update);
    return () => window.removeEventListener("popstate", update);
  }, [predicate]);

  return matches;
}

export function useCaptureMode(): boolean {
  return useLocationSearch(isCaptureModeSearch);
}

export function useReferenceEvidenceLabMode(): boolean {
  return useLocationSearch(isReferenceEvidenceLabSearch);
}
