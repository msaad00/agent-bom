"use client";

import {
  createContext,
  useContext,
  useMemo,
  useState,
  type Dispatch,
  type ReactNode,
  type SetStateAction,
} from "react";

type SidebarLayoutValue = {
  collapsed: boolean;
  setCollapsed: Dispatch<SetStateAction<boolean>>;
};

const SidebarLayoutContext = createContext<SidebarLayoutValue | null>(null);

/** Owns sidebar width so main content padding stays in sync (no overlay). */
export function SidebarLayoutProvider({ children }: { children: ReactNode }) {
  const [collapsed, setCollapsed] = useState(true);
  const value = useMemo(() => ({ collapsed, setCollapsed }), [collapsed]);
  return (
    <SidebarLayoutContext.Provider value={value}>{children}</SidebarLayoutContext.Provider>
  );
}

export function useSidebarLayout(): SidebarLayoutValue {
  const ctx = useContext(SidebarLayoutContext);
  if (!ctx) {
    throw new Error("useSidebarLayout must be used within SidebarLayoutProvider");
  }
  return ctx;
}

/** Desktop sidebar is fixed; padding reserves the same width so content never sits underneath. */
export function mainContentPaddingClass(collapsed: boolean): string {
  return collapsed ? "lg:pl-[60px]" : "lg:pl-[240px]";
}
