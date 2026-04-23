"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";

import { api, type AuthMeResponse } from "@/lib/api";

interface AuthContextValue {
  session: AuthMeResponse | null;
  loading: boolean;
  error: string | null;
  refresh: () => Promise<void>;
  hasCapability: (capability: string) => boolean;
}

const defaultContext: AuthContextValue = {
  session: null,
  loading: true,
  error: null,
  refresh: async () => {},
  hasCapability: () => false,
};

const AuthContext = createContext<AuthContextValue>(defaultContext);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [session, setSession] = useState<AuthMeResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const next = await api.getAuthMe();
      setSession(next);
    } catch (nextError) {
      setSession(null);
      setError(nextError instanceof Error ? nextError.message : "Failed to load auth session");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const value = useMemo<AuthContextValue>(
    () => ({
      session,
      loading,
      error,
      refresh,
      hasCapability: (capability: string) => Boolean(session?.role_summary?.capabilities.includes(capability)),
    }),
    [error, loading, refresh, session]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuthState(): AuthContextValue {
  return useContext(AuthContext);
}
