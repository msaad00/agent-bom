"use client";

import { useEffect } from "react";
import { ShieldX } from "lucide-react";

import { api } from "@/lib/api";
import { errorBoundaryMessage, errorReference } from "@/lib/error-boundary-message";

export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  const message = errorBoundaryMessage(error);
  const reference = errorReference(error.digest);

  useEffect(() => {
    void api
      .reportClientError({
        message,
        digest: reference ?? undefined,
        path: window.location.pathname,
        component: "global-error-boundary",
      })
      .catch(() => {});
  }, [message, reference]);

  return (
    <main className="flex h-[80vh] flex-col items-center justify-center gap-4 px-6 text-center">
      <ShieldX className="h-12 w-12 text-red-500" aria-hidden="true" />
      <h1 className="text-lg font-semibold text-[var(--foreground)]">Something went wrong</h1>
      <p className="max-w-md text-sm text-[var(--text-secondary)]">{message}</p>
      {reference ? (
        <p className="text-xs text-[var(--text-secondary)]">Reference: {reference}</p>
      ) : null}
      <button
        type="button"
        onClick={reset}
        className="rounded-md bg-emerald-600 px-4 py-2 text-sm text-white transition-colors hover:bg-emerald-500"
      >
        Try again
      </button>
    </main>
  );
}
