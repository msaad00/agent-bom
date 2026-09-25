"use client";

import { useEffect, useState, type ReactNode } from "react";

import { useAuthState } from "@/components/auth-provider";
import { BrandLogo } from "@/components/brand-logo";
import { api } from "@/lib/api";
import { ApiError } from "@/lib/api-errors";
import { clearSessionApiKey } from "@/lib/auth";
import { ssoLoginPreset } from "@/lib/sso-login-presets";

const AUTH_FAILURE_MESSAGE =
  "Sign-in failed. Check your API key or contact your administrator.";
const OIDC_BROWSER_LOGIN_PATH = "/v1/auth/oidc/login";
const SNOWFLAKE_OAUTH_LOGIN_PATH = "/v1/auth/snowflake/login";

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
  trialInvitation,
}: {
  title?: string;
  trialInvitation?: ReactNode;
}) {
  const { session, loading, error, refresh } = useAuthState();
  const [apiKey, setApiKey] = useState("");
  const [formError, setFormError] = useState<string | null>(null);
  const [authUnconfigured, setAuthUnconfigured] = useState(false);
  const signedIn = Boolean(session && (!session.auth_required || session.authenticated));

  useEffect(() => {
    if (loading || signedIn) return;
    api.health().then(
      (health) => setAuthUnconfigured(health.auth_configured === false && !health.unauthenticated_allowed),
      () => {},
    );
  }, [loading, signedIn]);

  if (loading) {
    return (
      <div className="flex min-h-[calc(100vh-4rem)] items-center justify-center">
        <span
          role="status"
          aria-label="Loading authentication"
          className="h-6 w-6 animate-spin rounded-full border-2 border-[var(--border-subtle)] border-t-emerald-400"
        />
      </div>
    );
  }

  if (signedIn) {
    return null;
  }

  if (error && isApiReachabilityFailure(error)) {
    return (
      <div className="flex min-h-[calc(100vh-4rem)] items-center justify-center px-4 py-6">
        <div className="w-full max-w-xl rounded-3xl border border-amber-900/50 bg-amber-950/20 p-8 text-center shadow-2xl shadow-black/20">
          <div className="mx-auto mb-4 flex justify-center">
            <BrandLogo />
          </div>
          <h1 className="text-xl font-semibold tracking-tight text-[var(--foreground)]">Control plane unreachable</h1>
          <p className="mt-3 text-sm leading-6 text-[var(--text-secondary)]">
            Authentication could not be verified because the API is offline or returned a server error. The dashboard
            stays locked until session discovery succeeds.
          </p>
          <p className="mt-2 text-xs text-[var(--text-tertiary)]">
            Try again, or contact your administrator if the problem continues.
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
    const snowflakeOauthConfigured = configuredModes.includes("snowflake_oauth");
    const ssoConfigured = browserOidcConfigured || snowflakeOauthConfigured;
    const trustedProxyConfigured = configuredModes.includes("trusted_proxy");
    const oidcBearerConfigured = configuredModes.includes("oidc_bearer");
    const proxyOrBearerHint = !ssoConfigured && (trustedProxyConfigured || oidcBearerConfigured);
    const showApiKeyDivider = ssoConfigured || proxyOrBearerHint;
    // An unauthenticated page load is not evidence that a submitted key was rejected.
    const shownError = formError;
    const rule = <span className="h-px flex-1 bg-[var(--surface-elevated)]" />;
    const ssoPreset = ssoLoginPreset(session?.sso_provider);
    const apiKeyDivider = (
      <div className="mt-6 flex items-center gap-3 text-[11px] uppercase tracking-[0.2em] text-[var(--text-tertiary)]">
        {rule}
        or use an API key
        {rule}
      </div>
    );

    return (
      <div className="flex min-h-[calc(100vh-4rem)] items-center justify-center px-4 py-6">
        <div className="w-full max-w-md rounded-2xl border border-[var(--border-subtle)] bg-[var(--background)]/80 p-5 sm:p-6 shadow-2xl shadow-black/20">
          <div className="mb-4 text-center">
            <div className="mx-auto mb-4 flex justify-center">
              <BrandLogo />
            </div>
            <h1 className="text-xl font-semibold tracking-tight text-[var(--foreground)]">{title}</h1>
            <p className="mt-1 text-sm text-[var(--text-secondary)]">
              {ssoConfigured
                ? `${browserOidcConfigured ? ssoPreset.buttonLabel : "Sign in with Snowflake"}, or use an API key as a fallback.`
                : "Enter your API key to access the dashboard."}
            </p>
          </div>

          {ssoConfigured ? (
            <div className="mb-6 space-y-3">
              {browserOidcConfigured ? (
                <a
                  href={OIDC_BROWSER_LOGIN_PATH}
                  className="login-sso-button login-sso-browser"
                >
                  {ssoPreset.buttonLabel}
                </a>
              ) : null}
              {snowflakeOauthConfigured ? (
                <a
                  href={SNOWFLAKE_OAUTH_LOGIN_PATH}
                  className={
                    browserOidcConfigured
                      ? "login-sso-button login-sso-secondary"
                      : "login-sso-button login-sso-snowflake"
                  }
                >
                  Sign in with Snowflake
                </a>
              ) : null}
              {showApiKeyDivider ? apiKeyDivider : null}
            </div>
          ) : null}

          {proxyOrBearerHint ? (
            <div className="mb-6">
              <p className="rounded-2xl border border-[var(--border-subtle)] bg-[var(--surface)]/60 px-4 py-3 text-center text-sm text-[var(--text-secondary)]">
                {trustedProxyConfigured
                  ? "Single sign-on is handled by your reverse proxy. Continue there, or use an API key below."
                  : "Single sign-on is handled by your identity provider or reverse proxy."}
              </p>
              {apiKeyDivider}
            </div>
          ) : null}

          {browserOidcConfigured ? trialInvitation : null}

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
                clearSessionApiKey();
                setApiKey("");
                const status = nextError instanceof ApiError ? nextError.status : undefined;
                const authFailure = status === 401 || status === 403 || (
                  status === undefined && nextError instanceof Error && isAuthFailure(nextError.message)
                );
                // Do not echo upstream response bodies or exception messages at the sign-in boundary.
                setFormError(authFailure ? AUTH_FAILURE_MESSAGE : status === 429
                  ? "Too many sign-in attempts. Wait a moment and try again."
                  : "Sign-in is unavailable. Try again, or contact your administrator.");
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
              <input
                id="agent-bom-browser-session-api-key"
                type="password"
                value={apiKey}
                onChange={(event) => setApiKey(event.target.value)}
                className="w-full rounded-xl border border-[var(--border-subtle)] bg-[var(--background)] px-3 py-2.5 font-mono text-sm text-[var(--foreground)] outline-none ring-0 placeholder:text-[var(--text-tertiary)] focus:border-emerald-500"
                placeholder="Paste your API key"
                autoComplete="off"
                autoFocus={!ssoConfigured}
              />
            </div>
            <p className="mt-2 text-xs leading-5 text-[var(--text-tertiary)]">
              {authUnconfigured ? (
                <>
                  No API key is configured on this server yet. Restart it with one:
                  <code className="block font-mono">agent-bom api --api-key &lt;your-key&gt;</code>
                  or, for local use only, without sign-in:
                  <code className="block font-mono">agent-bom api --allow-insecure-no-auth</code>
                </>
              ) : (
                "Need access? Contact your administrator."
              )}
            </p>

            <button
              type="submit"
              disabled={!apiKey.trim()}
              className={
                ssoConfigured
                  ? "login-submit login-submit-sso"
                  : "login-submit login-submit-key"
              }
            >
              Sign in
            </button>

            {shownError ? (
              <div role="alert" className="mt-3 rounded-xl border border-red-500/30 dark:border-red-900/50 bg-red-500/10 dark:bg-red-950/20 px-4 py-2.5 text-sm text-red-700 dark:text-red-300">
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
                Reset sign-in
              </button>
            </div>
          </form>

          {authUnconfigured ? null : <details className="mt-4 border-t border-[var(--border-subtle)] pt-3 text-sm text-[var(--text-secondary)]">
            <summary className="cursor-pointer font-medium">Sign-in help</summary>
            <p className="mt-2">Use the key provided by your administrator. Access permissions are managed by your organization.</p>
            {!ssoConfigured && !proxyOrBearerHint ? (
              <p className="mt-2">For single sign-on, ask your administrator to configure your organization's identity provider.</p>
            ) : null}
          </details>}
        </div>
      </div>
    );
  }

  return (
    <div className="flex min-h-[calc(100vh-4rem)] items-center justify-center px-4 py-6">
      <div className="max-w-xl rounded-2xl border border-red-500/30 dark:border-red-900/50 bg-red-500/10 dark:bg-red-950/20 p-6 text-sm text-red-700 dark:text-red-300">
        Try again, or contact your administrator if the problem continues.
      </div>
    </div>
  );
}
