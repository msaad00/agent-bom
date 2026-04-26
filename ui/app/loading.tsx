import { ShieldCheck } from "lucide-react";

export default function Loading() {
  return (
    <div className="min-h-[70vh] animate-pulse" role="status" aria-live="polite" aria-label="Loading dashboard">
      <div className="mb-6 flex items-center gap-3">
        <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-emerald-900/60 bg-emerald-950/30">
          <ShieldCheck className="h-5 w-5 text-emerald-400" aria-hidden="true" />
        </div>
        <div>
          <div className="h-4 w-36 rounded bg-zinc-800" />
          <div className="mt-2 h-3 w-56 rounded bg-zinc-900" />
        </div>
      </div>
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {["a", "b", "c", "d"].map((key) => (
          <div key={key} className="h-28 rounded-lg border border-zinc-800 bg-zinc-950" />
        ))}
      </div>
      <div className="mt-6 grid gap-4 lg:grid-cols-[1.7fr_1fr]">
        <div className="h-80 rounded-lg border border-zinc-800 bg-zinc-950" />
        <div className="h-80 rounded-lg border border-zinc-800 bg-zinc-950" />
      </div>
    </div>
  );
}
