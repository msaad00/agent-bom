"use client";

import { useEffect } from "react";
import { ShieldX } from "lucide-react";

import { api } from "@/lib/api";

export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    void api
      .reportClientError({
        message: error.message,
        digest: error.digest,
        path: typeof window === "undefined" ? "/" : window.location.pathname,
        component: "root-global-error-boundary",
      })
      .catch(() => {});
  }, [error]);

  return (
    <html lang="en">
      <body className="min-h-screen bg-zinc-950 text-zinc-100">
        <main className="flex min-h-screen flex-col items-center justify-center gap-4 px-6 text-center">
          <ShieldX className="h-12 w-12 text-red-500" aria-hidden="true" />
          <h1 className="text-lg font-semibold">Something went wrong</h1>
          <p className="max-w-md text-sm text-zinc-400">{error.message}</p>
          <button
            type="button"
            onClick={reset}
            className="rounded-md bg-emerald-600 px-4 py-2 text-sm text-white transition-colors hover:bg-emerald-500"
          >
            Try again
          </button>
        </main>
      </body>
    </html>
  );
}
