"use client";

import { ShieldX } from "lucide-react";

export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
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
