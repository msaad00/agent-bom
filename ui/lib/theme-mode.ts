import { useSyncExternalStore } from "react";

const THEME_STORAGE_KEY = "agent-bom-theme";

export type ThemeMode = "dark" | "light";

export function readThemeMode(): ThemeMode {
  if (typeof window === "undefined") return "dark";
  try {
    const stored = window.localStorage.getItem(THEME_STORAGE_KEY);
    if (stored === "light" || stored === "dark") return stored;
  } catch {
    // Ignore storage failures and fall back to the current root theme.
  }
  return document.documentElement.dataset.theme === "light" ? "light" : "dark";
}

export function subscribeThemeMode(onChange: () => void): () => void {
  if (typeof window === "undefined") return () => {};
  const handleChange = () => onChange();
  window.addEventListener("storage", handleChange);
  window.addEventListener("agent-bom-theme-change", handleChange);
  return () => {
    window.removeEventListener("storage", handleChange);
    window.removeEventListener("agent-bom-theme-change", handleChange);
  };
}

export function getThemeModeServerSnapshot(): ThemeMode {
  return "dark";
}

export function useThemeMode(): ThemeMode {
  return useSyncExternalStore(subscribeThemeMode, readThemeMode, getThemeModeServerSnapshot);
}
