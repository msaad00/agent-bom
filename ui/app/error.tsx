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
        path: window.location.pathname,
        component: "global-error-boundary",
      })
      .catch(() => {});
  }, [error]);

  return (
    <div className="flex flex-col items-center justify-center h-[80vh] gap-4 text-center">
      <ShieldX className="w-12 h-12 text-red-500" />
      <h2 className="text-lg font-semibold text-zinc-200">Something went wrong</h2>
      <p className="text-sm text-zinc-400 max-w-md">{error.message}</p>
      <button
        onClick={reset}
        className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 rounded-md text-sm text-white transition-colors"
      >
        Try again
      </button>
    </div>
  );
}
