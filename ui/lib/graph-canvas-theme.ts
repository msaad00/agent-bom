/**
 * Theme palette for the graph surfaces that draw into a canvas.
 *
 * The 2D overview and the sigma/WebGL stage cannot style themselves with CSS
 * classes, so they used to carry a private near-black palette: a `#050505`
 * stage with `#e4e4e7` labels, painted identically in both themes. On a light
 * page that made the largest element on the screen a black rectangle with its
 * own contrast rules.
 *
 * These read the same `globals.css` tokens every other surface uses, at draw
 * time, so the canvas tracks the theme. Fallbacks are the real dark token
 * values so a pre-computed-style render never flashes an invented colour.
 */

import { useMemo } from "react";

import { readThemeColor } from "@/lib/theme-colors";
import { useThemeMode, type ThemeMode } from "@/lib/theme-mode";

export interface GraphCanvasPalette {
  /** Stage fill behind the graph. */
  stage: string;
  /** Node labels drawn over the stage. */
  label: string;
  /** The selected node, which must read as brighter than every data colour. */
  selected: string;
  /** Nodes muted because something else is selected. */
  dimmed: string;
  /** Node with no type colour of its own. */
  defaultNode: string;
  /** Edge with no relationship colour of its own. */
  defaultEdge: string;
}

/**
 * Values of the same tokens in `globals.css`, used only when the computed
 * style is not available yet (server render, detached document). Keyed by
 * mode so a light-theme first paint never flashes the dark stage.
 */
const TOKEN_FALLBACKS: Record<ThemeMode, Record<string, string>> = {
  dark: {
    "--background": "#14161d",
    "--foreground": "#f4f5f8",
    "--text-secondary": "#d0d4dc",
    "--text-tertiary": "#a8aebc",
  },
  light: {
    "--background": "#e6eaf1",
    "--foreground": "#12141a",
    "--text-secondary": "#374151",
    "--text-tertiary": "#55627a",
  },
};

export function getGraphCanvasPalette(mode: ThemeMode = "dark"): GraphCanvasPalette {
  const token = (name: keyof (typeof TOKEN_FALLBACKS)["dark"]) =>
    readThemeColor(name, TOKEN_FALLBACKS[mode][name]!);
  const foreground = token("--foreground");
  const tertiary = token("--text-tertiary");
  return {
    stage: token("--background"),
    label: foreground,
    selected: foreground,
    dimmed: tertiary,
    defaultNode: tertiary,
    defaultEdge: token("--text-secondary"),
  };
}

/**
 * Hook variant. Subscribes to the theme mode so the canvas redraws — and
 * re-reads the tokens — the moment the user flips light/dark, instead of
 * keeping the previous theme's paint until the next data-driven render.
 *
 * The result is memoised on the theme mode because the WebGL renderer takes
 * the palette as a construction option: a fresh object every render would
 * re-create the renderer on every render, and the renderer sets state.
 */
export function useGraphCanvasPalette(): GraphCanvasPalette {
  const mode = useThemeMode();
  return useMemo(() => getGraphCanvasPalette(mode), [mode]);
}
