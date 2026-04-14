"use client";

import { Moon, Sun } from "lucide-react";
import { useEffect, useState } from "react";

const THEME_STORAGE_KEY = "agent-bom-theme";

type ThemeMode = "dark" | "light";

function readTheme(): ThemeMode {
  if (typeof window === "undefined") return "dark";
  try {
    const stored = window.localStorage.getItem(THEME_STORAGE_KEY);
    if (stored === "light" || stored === "dark") return stored;
  } catch {
    // Ignore storage failures and fall back to the current root theme.
  }
  return document.documentElement.dataset.theme === "light" ? "light" : "dark";
}

function applyTheme(theme: ThemeMode) {
  const root = document.documentElement;
  root.dataset.theme = theme;
  root.style.colorScheme = theme;
  try {
    window.localStorage.setItem(THEME_STORAGE_KEY, theme);
  } catch {
    // Ignore storage failures; the theme still applies for this session.
  }
}

export function ThemeToggle({ compact = false, className = "" }: { compact?: boolean; className?: string }) {
  const [theme, setTheme] = useState<ThemeMode>("dark");

  useEffect(() => {
    const initial = readTheme();
    setTheme(initial);
    applyTheme(initial);
  }, []);

  const nextTheme = theme === "dark" ? "light" : "dark";
  const label = theme === "dark" ? "Switch to light theme" : "Switch to dark theme";

  return (
    <button
      type="button"
      onClick={() => {
        setTheme(nextTheme);
        applyTheme(nextTheme);
      }}
      className={`inline-flex items-center gap-2 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] text-[color:var(--foreground)] transition-colors hover:bg-[color:var(--surface-elevated)] ${compact ? "h-9 w-9 justify-center p-0" : "h-9 px-3 text-xs font-medium"} ${className}`}
      title={label}
      aria-label={label}
    >
      {theme === "dark" ? <Moon className="h-4 w-4 shrink-0" /> : <Sun className="h-4 w-4 shrink-0" />}
      {!compact && (
        <span className="truncate">
          {theme === "dark" ? "Dark theme" : "Light theme"}
        </span>
      )}
    </button>
  );
}
