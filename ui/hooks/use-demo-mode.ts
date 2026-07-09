"use client";

import { useEffect, useState } from "react";

import { useAuthState } from "@/components/auth-provider";
import { api, type HealthResponse } from "@/lib/api";

/**
 * Detects the public demo deployment: the API is running with
 * ``AGENT_BOM_ALLOW_UNAUTHENTICATED_API=1`` (so ``/health`` reports
 * ``unauthenticated_allowed`` with no real auth configured) and the current
 * viewer is the anonymous, read-only demo viewer rather than a signed-in user.
 *
 * Both signals are read from endpoints the UI already calls — ``/health`` via
 * ``api.health()`` and ``/v1/auth/me`` via {@link useAuthState} — so nothing is
 * hardcoded. Returns ``isDemoMode: false`` until both signals resolve to avoid
 * flashing the banner during bootstrap on authenticated deployments.
 */
export function useDemoMode(): { isDemoMode: boolean; loading: boolean } {
  const { session, loading: authLoading } = useAuthState();
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [healthLoading, setHealthLoading] = useState(true);

  useEffect(() => {
    let mounted = true;
    api
      .health()
      .then((next) => {
        if (!mounted) return;
        setHealth(next);
      })
      .catch(() => {
        if (!mounted) return;
        setHealth(null);
      })
      .finally(() => {
        if (mounted) setHealthLoading(false);
      });
    return () => {
      mounted = false;
    };
  }, []);

  const loading = authLoading || healthLoading;

  // Server is in open/demo posture: anonymous access is allowed and no real
  // auth provider is configured.
  const serverIsOpen = Boolean(health?.unauthenticated_allowed) && !health?.auth_configured;

  // The viewer is anonymous — a signed-in user on the same deployment must not
  // see the "sign in" funnel.
  const viewerIsAnonymous = session ? !session.authenticated : true;

  const isDemoMode = !loading && serverIsOpen && viewerIsAnonymous;

  return { isDemoMode, loading };
}
