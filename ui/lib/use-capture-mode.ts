"use client";

import { useEffect, useState } from "react";

export function isCaptureModeSearch(search: string): boolean {
  return new URLSearchParams(search).get("capture") === "1";
}

function readCaptureModeFromLocation(): boolean {
  if (typeof window === "undefined") return false;
  return isCaptureModeSearch(window.location.search);
}

export function useCaptureMode(): boolean {
  // Defer URL reads until after mount so SSR and the first client paint match.
  const [captureMode, setCaptureMode] = useState(false);

  useEffect(() => {
    const update = () => setCaptureMode(readCaptureModeFromLocation());
    update();
    window.addEventListener("popstate", update);
    return () => window.removeEventListener("popstate", update);
  }, []);

  return captureMode;
}
