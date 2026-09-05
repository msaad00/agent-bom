"use client";

import { useEffect } from "react";
import { usePathname, useRouter } from "next/navigation";
import { FileText, Loader2, WifiOff } from "lucide-react";

import { useAuthState } from "@/components/auth-provider";
import { BrandLogo } from "@/components/brand-logo";
import {
  disableOfflineReportMode,
  enableOfflineReportMode,
  useOfflineReportMode,
} from "@/lib/offline-report-mode";

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

/**
 * Offered on every screen that would otherwise dead-end a user holding a
 * report file. Pressing it renders the app so the in-browser report importer
 * can mount; it grants no data, because the API is still unreachable or still
 * refusing this session.
 */
function ContinueOfflineButton() {
  return (
    <button
      type="button"
      onClick={enableOfflineReportMode}
      className="mt-5 inline-flex items-center gap-2 rounded-lg border border-[var(--border-subtle)] bg-[var(--surface-elevated)] px-4 py-2 text-sm text-[var(--foreground)] transition-colors hover:bg-[var(--surface-muted)]"
    >
      <FileText className="h-4 w-4" />
      Continue offline with a report file
    </button>
  );
}

export function AuthGate({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  const { session, loading, error, reconnecting } = useAuthState();
  const offlineReportMode = useOfflineReportMode();

  const needsAuth =
    !loading &&
    (!session || (session.auth_required && !session.authenticated)) &&
    (!error || isAuthFailure(error));

  useEffect(() => {
    if (!needsAuth || offlineReportMode || pathname === "/login") return;
    const returnTo = encodeURIComponent(`${pathname || "/"}${window.location.search}${window.location.hash}`);
    router.replace(`/login?returnTo=${returnTo}`);
  }, [needsAuth, offlineReportMode, pathname, router]);

  if (loading) {
    return (
      <div className="flex min-h-[calc(100vh-5rem)] flex-col items-center justify-center gap-3">
        <Loader2 className="h-6 w-6 animate-spin text-[var(--text-tertiary)]" />
        {reconnecting ? (
          <p className="text-xs text-[var(--text-tertiary)]">Reconnecting to the control plane…</p>
        ) : null}
      </div>
    );
  }

  if (session && (!session.auth_required || session.authenticated)) {
    return <>{children}</>;
  }

  // The user asked to work from a local report. Say so plainly — nothing on
  // screen below this banner came from the control plane — and keep the way
  // back to signing in one click away.
  if (offlineReportMode) {
    return (
      <>
        <div
          role="status"
          className="mb-4 flex flex-wrap items-center gap-x-3 gap-y-2 rounded-xl border border-amber-500/40 bg-amber-500/10 dark:bg-amber-950/25 px-4 py-2.5 text-sm text-amber-900 dark:text-amber-100"
        >
          <WifiOff className="h-4 w-4 shrink-0" />
          <span className="min-w-0">
            Offline. Not signed in to the control plane — only a report you import here is shown.
          </span>
          <button
            type="button"
            onClick={() => {
              disableOfflineReportMode();
              router.replace("/login");
            }}
            className="ml-auto shrink-0 rounded-lg border border-[var(--border-subtle)] bg-[var(--surface-elevated)] px-3 py-1.5 text-xs text-[var(--foreground)] transition-colors hover:bg-[var(--surface-muted)]"
          >
            Sign in
          </button>
        </div>
        {children}
      </>
    );
  }

  if (error && isApiReachabilityFailure(error)) {
    return (
      <div className="flex min-h-[calc(100vh-5rem)] items-center justify-center px-4 py-10">
        <div className="w-full max-w-xl rounded-3xl border border-amber-500/40 bg-amber-500/10 dark:border-amber-900/50 dark:bg-amber-950/20 p-8 text-center shadow-2xl shadow-black/20">
          <div className="mx-auto mb-4 flex justify-center">
            <BrandLogo />
          </div>
          <h1 className="text-xl font-semibold tracking-tight text-[var(--foreground)]">Control plane unreachable</h1>
          <p className="mt-3 text-sm leading-6 text-[var(--text-secondary)]">
            Authentication could not be verified because the API is offline or returned a server error.
          </p>
          <p className="mt-2 text-xs text-[var(--text-tertiary)]">{error}</p>
          <ContinueOfflineButton />
        </div>
      </div>
    );
  }

  if (needsAuth) {
    return (
      <div className="flex min-h-[calc(100vh-5rem)] items-center justify-center">
        <Loader2 className="h-6 w-6 animate-spin text-[var(--text-tertiary)]" />
      </div>
    );
  }

  return (
    <div className="flex min-h-[calc(100vh-5rem)] flex-col items-center justify-center px-4 py-10">
      <div className="max-w-xl rounded-2xl border border-red-500/30 dark:border-red-900/50 bg-red-500/10 dark:bg-red-950/20 p-6 text-sm text-red-700 dark:text-red-300">{error}</div>
      <ContinueOfflineButton />
    </div>
  );
}
