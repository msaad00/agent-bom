"use client";

import { useState } from "react";
import { KeyRound, Loader2, Lock, ShieldCheck } from "lucide-react";

import { useAuthState } from "@/components/auth-provider";
import { api } from "@/lib/api";
import { clearSessionApiKey } from "@/lib/auth";

function isAuthFailure(message: string): boolean {
  const normalized = message.toLowerCase();
  return normalized.includes("unauthorized") || normalized.includes("invalid api key") || normalized.includes("forbidden");
}

export function AuthGate({ children }: { children: React.ReactNode }) {
  const { session, loading, error, refresh } = useAuthState();
  const [apiKey, setApiKey] = useState("");
  const [formError, setFormError] = useState<string | null>(null);

  if (loading) {
    return (
      <div className="flex min-h-[calc(100vh-4rem)] items-center justify-center">
        <Loader2 className="h-6 w-6 animate-spin text-zinc-500" />
      </div>
    );
  }

  if (session && (!session.auth_required || session.authenticated)) {
    return <>{children}</>;
  }

  if (!error || isAuthFailure(error)) {
    return (
      <div className="flex min-h-[calc(100vh-4rem)] items-center justify-center px-4 py-10">
        <div className="w-full max-w-2xl rounded-3xl border border-zinc-800 bg-zinc-950/80 p-8 shadow-2xl shadow-black/20">
          <div className="mb-6 flex items-center gap-3 text-zinc-100">
            <ShieldCheck className="h-6 w-6 text-emerald-400" />
            <div>
              <h1 className="text-xl font-semibold tracking-tight">Control-plane authentication required</h1>
              <p className="mt-1 text-sm text-zinc-400">
                Recommended for enterprise: same-origin reverse-proxy OIDC/session auth. For single-user local or pilot access, enter a short-lived API key for this browser session only.
              </p>
            </div>
          </div>

          <div className="grid gap-4 md:grid-cols-2">
            <div className="rounded-2xl border border-emerald-900/60 bg-emerald-950/20 p-5">
              <div className="mb-2 flex items-center gap-2 text-sm font-semibold text-emerald-300">
                <Lock className="h-4 w-4" />
                Recommended: reverse-proxy OIDC
              </div>
              <p className="text-sm leading-6 text-zinc-400">
                Keep the UI and API on the same origin, terminate browser auth at the proxy, and inject trusted
                <code className="mx-1 rounded bg-zinc-900 px-1 py-0.5 font-mono text-zinc-200">X-Agent-Bom-Role</code>
                plus
                <code className="mx-1 rounded bg-zinc-900 px-1 py-0.5 font-mono text-zinc-200">X-Agent-Bom-Tenant-ID</code>
                headers upstream.
              </p>
            </div>

            <form
              className="rounded-2xl border border-zinc-800 bg-zinc-900/60 p-5"
              onSubmit={async (event) => {
                event.preventDefault();
                setFormError(null);
                try {
                  await api.createAuthSession(apiKey);
                  clearSessionApiKey();
                } catch (nextError) {
                  const message = nextError instanceof Error ? nextError.message : "Failed to create browser session";
                  if (message.includes("404") || message.includes("405")) {
                    clearSessionApiKey();
                    setFormError("Browser session endpoint unavailable; update the API before using browser API-key exchange.");
                    return;
                  } else {
                    clearSessionApiKey();
                    setFormError(message);
                    return;
                  }
                }
                await refresh();
              }}
            >
              <div className="mb-2 flex items-center gap-2 text-sm font-semibold text-zinc-200">
                <KeyRound className="h-4 w-4 text-amber-300" />
                Browser session
              </div>
              <p className="mb-4 text-sm leading-6 text-zinc-400">
                Creates a same-origin
                <code className="mx-1 rounded bg-zinc-950 px-1 py-0.5 font-mono text-zinc-200">httpOnly</code>
                cookie. The API key is exchanged with the control plane and is never stored in browser storage.
              </p>
              <label htmlFor="agent-bom-browser-session-api-key" className="mb-3 block text-xs uppercase tracking-[0.2em] text-zinc-500">
                API key
              </label>
              <input
                id="agent-bom-browser-session-api-key"
                type="password"
                value={apiKey}
                onChange={(event) => setApiKey(event.target.value)}
                className="w-full rounded-xl border border-zinc-700 bg-zinc-950 px-3 py-2 font-mono text-sm text-zinc-100 outline-none ring-0 placeholder:text-zinc-600 focus:border-emerald-500"
                placeholder="abk_..."
                autoComplete="off"
              />
              <div className="mt-4 flex gap-3">
                <button
                  type="submit"
                  className="rounded-xl bg-emerald-500 px-4 py-2 text-sm font-medium text-zinc-950 transition hover:bg-emerald-400"
                >
                  Unlock dashboard
                </button>
                <button
                  type="button"
                  onClick={async () => {
                    try {
                      await api.deleteAuthSession();
                    } catch {
                      // Older API versions may not expose the cookie session endpoint.
                    }
                    clearSessionApiKey();
                    setFormError(null);
                    setApiKey("");
                    await refresh();
                  }}
                  className="rounded-xl border border-zinc-700 px-4 py-2 text-sm text-zinc-300 transition hover:bg-zinc-900"
                >
                  Clear key
                </button>
              </div>
            </form>
          </div>

          {error ? (
            <div className="mt-5 rounded-2xl border border-red-900/50 bg-red-950/20 px-4 py-3 text-sm text-red-300">
              {error}
            </div>
          ) : null}
          {formError ? (
            <div className="mt-5 rounded-2xl border border-red-900/50 bg-red-950/20 px-4 py-3 text-sm text-red-300">
              {formError}
            </div>
          ) : null}
        </div>
      </div>
    );
  }

  return (
    <div className="flex min-h-[calc(100vh-4rem)] items-center justify-center px-4 py-10">
      <div className="max-w-xl rounded-2xl border border-red-900/50 bg-red-950/20 p-6 text-sm text-red-300">
        {error}
      </div>
    </div>
  );
}
