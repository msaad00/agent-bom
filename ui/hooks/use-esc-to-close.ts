"use client";

import { useEffect } from "react";

/**
 * Close an overlay when Escape is pressed. Pass `active` so the listener is only
 * bound while the overlay is open (custom drawers that early-return null must
 * still call the hook unconditionally to satisfy the rules of hooks).
 */
export function useEscToClose(active: boolean, onClose: () => void): void {
  useEffect(() => {
    if (!active) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [active, onClose]);
}
