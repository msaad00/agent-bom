"use client";

import { useCallback, useEffect, useState } from "react";

/** Shared, persisted width for right-hand slide-over drawers.
 *
 * A fixed drawer width forces long values to wrap and wastes the row on short
 * ones. Readers size it to what they are reading, and the choice sticks — a
 * width you have to re-drag on every open is worse than no control at all.
 */

const STORAGE_KEY = "agent-bom-drawer-width";
const DEFAULT_WIDTH = 512; // matches the previous max-w-lg
const MIN_WIDTH = 360;
const KEYBOARD_STEP = 48;

function maxWidth(): number {
  // Never let a drawer swallow the page it is describing.
  if (typeof window === "undefined") return 960;
  return Math.max(MIN_WIDTH, Math.round(window.innerWidth * 0.9));
}

function clamp(value: number): number {
  return Math.min(maxWidth(), Math.max(MIN_WIDTH, Math.round(value)));
}

export function useDrawerWidth() {
  const [width, setWidth] = useState<number>(DEFAULT_WIDTH);

  // Read after mount so server and client render the same markup.
  //
  // Guarded: Storage is absent or throws in private-browsing and blocked-cookie
  // contexts. A remembered width is a convenience — losing it must never stop
  // the drawer rendering.
  useEffect(() => {
    try {
      const stored = Number(window.localStorage?.getItem(STORAGE_KEY));
      if (Number.isFinite(stored) && stored > 0) setWidth(clamp(stored));
    } catch {
      // Keep the default width.
    }
  }, []);

  const persist = useCallback((next: number) => {
    const clamped = clamp(next);
    setWidth(clamped);
    try {
      window.localStorage?.setItem(STORAGE_KEY, String(clamped));
    } catch {
      // A blocked or absent Storage must not break resizing.
    }
  }, []);

  const onHandlePointerDown = useCallback(
    (event: React.PointerEvent<HTMLElement>) => {
      event.preventDefault();
      // The drawer is right-anchored, so dragging the left edge leftward widens
      // it: width tracks the distance from the pointer to the right edge.
      const move = (moveEvent: PointerEvent) => {
        persist(window.innerWidth - moveEvent.clientX);
      };
      const up = () => {
        window.removeEventListener("pointermove", move);
        window.removeEventListener("pointerup", up);
      };
      window.addEventListener("pointermove", move);
      window.addEventListener("pointerup", up);
    },
    [persist],
  );

  const onHandleKeyDown = useCallback(
    (event: React.KeyboardEvent<HTMLElement>) => {
      // Keyboard parity: a pointer-only resize is unusable for anyone who
      // cannot drag, and the handle is focusable.
      if (event.key === "ArrowLeft") {
        event.preventDefault();
        persist(width + KEYBOARD_STEP);
      } else if (event.key === "ArrowRight") {
        event.preventDefault();
        persist(width - KEYBOARD_STEP);
      }
    },
    [persist, width],
  );

  return { width, onHandlePointerDown, onHandleKeyDown };
}
