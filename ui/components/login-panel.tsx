"use client";

import { useState } from "react";
import { KeyRound, Loader2, ShieldCheck } from "lucide-react";

import { useAuthState } from "@/components/auth-provider";
import { BrandLogo } from "@/components/brand-logo";
import { api } from "@/lib/api";
import { userFacingApiErrorMessage } from "@/lib/api-errors";
import { clearSessionApiKey } from "@/lib/auth";

const AUTH_FAILURE_MESSAGE = "That API key wasn't accepted — check it and try again.";
const OIDC_BROWSER_LOGIN_PATH = "/v1/auth/oidc/login";

function isAuthFailure(message: string): boolean {
  const normalized = message.toLowerCase();
  return normalized.includes("unauthorized") || normalized.includes("invalid api key") || normalized.includes("forbidden");
}

function isApiReachabilityFailure(message: string): boolean {
  const normalized = message.toLowerCase();
  return (
    normalized.includes("network request failed") ||
    normalized.includes("failed to fetch") ||
    normalized.includes("econnrefused") ||
    normalized.includes("500 internal server error") ||
    normalized.includes("502 bad gateway") ||
    normalized.includes("503 service unavailable") ||
    normalized.includes("504 gateway timeout") ||
    normalized.includes("timed out") ||
    normalized.includes("timeout")
  );
}

export function LoginPanel({
  title = "Sign in to agent-bom",
}: {
  title?: string;
}) {
  const { session, loading, error, refresh } = useAuthState();
  const [apiKey, setApiKey] = useState("");
  const [formError, setFormError] = useState<string | null>(null);

  if (loading) {
    return (
      <div className="flex min-h-[calc(100vh-4rem)] items-center justify-center">
        <Loader2 className="h-6 w-6 animate-spin text-[var(--text-tertiary)]" />
      </div>
    );
  }

  if (session && (!session.auth_required || session.authenticated)) {
    return null;
  }

  if (error && isApiReachabilityFailure(error)) {
    return (
      <div className="flex min-h-[calc(100vh-4rem)] items-center justify-center px-4 py-10">
        <div className="w-full max-w-xl rounded-3xl border border-amber-900/50 bg-amber-950/20 p-8 text-center shadow-2xl shadow-black/20">
          <ShieldCheck className="mx-auto mb-4 h-8 w-8 text-amber-300" />
          <h1 className="text-xl font-semibold tracking-tight text-[var(--foreground)]">Control plane unreachable</h1>
          <p className="mt-3 text-sm leading-6 text-[var(--text-secondary)]">
            Authentication could not be verified because the API is offline or returned a server error. The dashboard
            stays locked until session discovery succeeds.
          </p>
          <p className="mt-2 text-xs text-[var(--text-tertiary)]">
            {userFacingApiErrorMessage(error, "Failed to load auth session")}
          </p>
          <button
            type="button"
            onClick={() => void refresh()}
            className="mt-6 rounded-xl bg-emerald-500 px-4 py-2 text-sm font-medium text-[var(--on-accent)] transition hover:bg-emerald-400"
          >
            Retry connection
          </button>
        </div>
      </div>
    );
  }

  if (!error || isAuthFailure(error)) {
    const configuredModes = session?.configured_modes ?? [];
    const browserOidcConfigured = configuredModes.includes("oidc_browser");
    const trustedProxyConfigured = configuredModes.includes("trusted_proxy");
    const oidcBearerConfigured = configuredModes.includes("oidc_bearer");
    const proxyOrBearerHint = !browserOidcConfigured && (trustedProxyConfigured || oidcBearerConfigured);
    const showApiKeyDivider = browserOidcConfigured || proxyOrBearerHint;
    const authError = error && isAuthFailure(error) ? AUTH_FAILURE_MESSAGE : null;
    const shownError = formError ?? authError;

    return (
      <div className="flex min-h-[calc(100vh-4rem)] items-center justify-center px-4 py-10">
        <div className="w-full max-w-md rounded-3xl border border-[var(--border-subtle)] bg-[var(--background)]/80 p-8 shadow-2xl shadow-black/20">
          <div className="mb-6 text-center">
            <div className="mx-auto mb-4 flex justify-center">
              <BrandLogo />
            </div>
            <h1 className="text-xl font-semibold tracking-tight text-[var(--foreground)]">{title}</h1>
            <p className="mt-1 text-sm text-[var(--text-secondary)]">
              {browserOidcConfigured
                ? "Sign in with SSO, or use an API key as a fallback."
                : "Enter your API key to access the dashboard."}
            </p>
          </div>

          {browserOidcConfigured ? (
            <div className="mb-6">
              <a
                href={OIDC_BROWSER_LOGIN_PATH}
                className="flex w-full items-center justify-center rounded-xl bg-emerald-500 px-4 py-2.5 text-sm font-medium text-[var(--on-accent)] transition hover:bg-emerald-400"
              >
                Sign in with SSO
              </a>
              {showApiKeyDivider ? (
                <div className="mt-6 flex items-center gap-3 text-[11px] uppercase tracking-[0.2em] text-[var(--text-tertiary)]">
                  <span className="h-px flex-1 bg-[var(--surface-elevated)]" />
                  or use an API key
                  <span className="h-px flex-1 bg-[var(--surface-elevated)]" />
                </div>
              ) : null}
            </div>
          ) : null}

          {proxyOrBearerHint ? (
            <div className="mb-6">
              <p className="rounded-2xl border border-[var(--border-subtle)] bg-[var(--surface)]/60 px-4 py-3 text-center text-sm text-[var(--text-secondary)]">
                {trustedProxyConfigured
                  ? "Single sign-on is handled by your reverse proxy. Continue there, or use an API key below."
                  : "Single sign-on is handled by your identity provider or reverse proxy."}
              </p>
              <div className="mt-6 flex items-center gap-3 text-[11px] uppercase tracking-[0.2em] text-[var(--text-tertiary)]">
                <span className="h-px flex-1 bg-[var(--surface-elevated)]" />
                or use an API key
                <span className="h-px flex-1 bg-[var(--surface-elevated)]" />
              </div>
            </div>
          ) : null}

          <form
            onSubmit={async (event) => {
              event.preventDefault();
              setFormError(null);
              const trimmedApiKey = apiKey.trim();
              if (!trimmedApiKey) {
                setFormError("Enter an API key to sign in.");
                return;
              }
              try {
                await api.createAuthSession(trimmedApiKey);
                clearSessionApiKey();
              } catch (nextError) {
                const message = userFacingApiErrorMessage(nextError, "Failed to create browser session");
                clearSessionApiKey();
                if (message.includes("404") || message.includes("405")) {
                  setFormError("Browser session endpoint unavailable; update the API before using browser API-key exchange.");
                  return;
                }
                setFormError(isAuthFailure(message) ? AUTH_FAILURE_MESSAGE : message);
                return;
              }
              await refresh();
            }}
          >
            <label
              htmlFor="agent-bom-browser-session-api-key"
              className="mb-2 block text-xs uppercase tracking-[0.2em] text-[var(--text-tertiary)]"
            >
              API key
            </label>
            <div className="relative">
              <KeyRound className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[var(--text-tertiary)]" />
              <input
                id="agent-bom-browser-session-api-key"
                type="password"
                value={apiKey}
                onChange={(event) => setApiKey(event.target.value)}
                className="w-full rounded-xl border border-[var(--border-subtle)] bg-[var(--background)] py-2.5 pl-9 pr-3 font-mono text-sm text-[var(--foreground)] outline-none ring-0 placeholder:text-[var(--text-tertiary)] focus:border-emerald-500"
                placeholder="Paste your API key"
                autoComplete="off"
                autoFocus={!browserOidcConfigured}
              />
            </div>
            <p className="mt-2 text-xs leading-5 text-[var(--text-tertiary)]">
              No key yet? Server operators set API keys via the{" "}
              <code className="rounded bg-[var(--surface)] px-1 py-0.5 font-mono text-[var(--text-secondary)]">AGENT_BOM_API_KEYS</code> env var
              (format{" "}
              <code className="rounded bg-[var(--surface)] px-1 py-0.5 font-mono text-[var(--text-secondary)]">&lt;key&gt;:&lt;admin|analyst|viewer&gt;</code>).
            </p>

            <button
              type="submit"
              disabled={!apiKey.trim()}
              className={
                browserOidcConfigured
                  ? "mt-5 w-full rounded-xl border border-[var(--border-subtle)] bg-[var(--surface)] px-4 py-2.5 text-sm font-medium text-[var(--foreground)] transition hover:border-[var(--border-strong)] hover:bg-[var(--surface-elevated)] disabled:cursor-not-allowed disabled:border-[var(--border-subtle)] disabled:bg-[var(--background)] disabled:text-[var(--text-tertiary)]"
                  : "mt-5 w-full rounded-xl bg-emerald-500 px-4 py-2.5 text-sm font-medium text-[var(--on-accent)] transition hover:bg-emerald-400 disabled:cursor-not-allowed disabled:bg-[var(--surface-elevated)] disabled:text-[var(--text-tertiary)]"
              }
            >
              Sign in
            </button>

            {shownError ? (
              <div className="mt-4 rounded-xl border border-red-900/50 bg-red-950/20 px-4 py-2.5 text-sm text-red-300">
                {shownError}
              </div>
            ) : null}

            <div className="mt-4 text-center">
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
                className="text-xs text-[var(--text-tertiary)] underline-offset-4 transition hover:text-[var(--text-secondary)] hover:underline"
              >
                Clear
              </button>
            </div>
          </form>

          {!browserOidcConfigured && !proxyOrBearerHint ? (
            <p className="mt-6 border-t border-[var(--border-subtle)] pt-4 text-center text-xs text-[var(--text-tertiary)]">
              Setting up single sign-on? Configure browser OIDC, a reverse proxy, or an OIDC issuer in your deployment.
            </p>
          ) : null}
        </div>
      </div>
    );
  }

  return (
    <div className="flex min-h-[calc(100vh-4rem)] items-center justify-center px-4 py-10">
      <div className="max-w-xl rounded-2xl border border-red-900/50 bg-red-950/20 p-6 text-sm text-red-300">
        {userFacingApiErrorMessage(error, "Failed to load auth session")}
      </div>
    </div>
  );
}
