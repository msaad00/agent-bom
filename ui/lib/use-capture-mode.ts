"use client";

import { useEffect, useState } from "react";

export function isCaptureModeSearch(search: string): boolean {
  return new URLSearchParams(search).get("capture") === "1";
}

export function useCaptureMode(): boolean {
  const [captureMode, setCaptureMode] = useState(false);

  useEffect(() => {
    const update = () => setCaptureMode(isCaptureModeSearch(window.location.search));
    update();
    window.addEventListener("popstate", update);
    return () => window.removeEventListener("popstate", update);
  }, []);

  return captureMode;
}
