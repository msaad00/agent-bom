"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";

import { api, type AuthMeResponse } from "@/lib/api";
import {
  ApiAuthError,
  ApiForbiddenError,
  ApiNetworkError,
  ApiServerError,
  userFacingApiErrorMessage,
} from "@/lib/api-errors";

interface AuthContextValue {
  session: AuthMeResponse | null;
  loading: boolean;
  error: string | null;
  /**
   * True while the probe is silently retrying a transient/aborted fetch. Lets
   * the gate show a subtle "reconnecting…" hint instead of the scary fatal
   * "control plane unreachable" screen on the first aborted request.
   */
  reconnecting: boolean;
  refresh: () => Promise<void>;
  hasCapability: (capability: string) => boolean;
}

const defaultContext: AuthContextValue = {
  session: null,
  loading: true,
  error: null,
  reconnecting: false,
  refresh: async () => {},
  hasCapability: () => false,
};

const AuthContext = createContext<AuthContextValue>(defaultContext);

// Next dev on-demand compilation and route navigation routinely abort the
// bootstrap auth probe (AbortError / TimeoutError). A single aborted or
// transient network hiccup should never surface the fatal "control plane
// unreachable" state — retry a few times with backoff first. A genuine,
// repeated connection refusal still fails all attempts and shows the fatal UI.
const MAX_PROBE_ATTEMPTS = 3;
const PROBE_RETRY_BASE_MS = 150;

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function isRetryableProbeError(err: unknown): boolean {
  // Auth/authorization outcomes are terminal — the operator must sign in.
  if (err instanceof ApiAuthError || err instanceof ApiForbiddenError) return false;
  // Aborted fetches, timeouts, and refused connections all arrive as
  // ApiNetworkError; transient 5xx as ApiServerError. Retry both.
  if (err instanceof ApiNetworkError || err instanceof ApiServerError) return true;
  const message = (err instanceof Error ? err.message : String(err)).toLowerCase();
  return (
    message.includes("abort") ||
    message.includes("timeout") ||
    message.includes("timed out") ||
    message.includes("network")
  );
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [session, setSession] = useState<AuthMeResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [reconnecting, setReconnecting] = useState(false);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    setReconnecting(false);
    for (let attempt = 1; attempt <= MAX_PROBE_ATTEMPTS; attempt += 1) {
      try {
        const next = await api.getAuthMe();
        setSession(next);
        setError(null);
        setReconnecting(false);
        setLoading(false);
        return;
      } catch (nextError) {
        if (isRetryableProbeError(nextError) && attempt < MAX_PROBE_ATTEMPTS) {
          // Silent recovery: keep the gate in its loading/reconnecting state
          // rather than flashing the fatal screen for a single aborted fetch.
          setReconnecting(true);
          await delay(PROBE_RETRY_BASE_MS * attempt);
          continue;
        }
        setSession(null);
        setError(userFacingApiErrorMessage(nextError, "Failed to load auth session"));
        setReconnecting(false);
        setLoading(false);
        return;
      }
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
      reconnecting,
      refresh,
      hasCapability: (capability: string) => Boolean(session?.role_summary?.capabilities.includes(capability)),
    }),
    [error, loading, reconnecting, refresh, session]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuthState(): AuthContextValue {
  return useContext(AuthContext);
}
