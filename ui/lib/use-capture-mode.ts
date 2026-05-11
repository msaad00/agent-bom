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
  const [captureMode, setCaptureMode] = useState(readCaptureModeFromLocation);

  useEffect(() => {
    const update = () => setCaptureMode(readCaptureModeFromLocation());
    window.addEventListener("popstate", update);
    return () => window.removeEventListener("popstate", update);
  }, []);

  return captureMode;
}
