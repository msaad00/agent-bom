"use client";

import { createContext, useContext } from "react";

const RuntimeEmbedContext = createContext(false);

export function RuntimeEmbedProvider({ children }: { children: React.ReactNode }) {
  return <RuntimeEmbedContext.Provider value>{children}</RuntimeEmbedContext.Provider>;
}

export function useRuntimeEmbedded(): boolean {
  return useContext(RuntimeEmbedContext);
}
