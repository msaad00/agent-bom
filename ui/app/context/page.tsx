"use client";

import { Suspense, useEffect } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { Loader2 } from "lucide-react";

// The Context lens now lives on the unified `/graph` surface, selected with
// `?lens=context` (graph-unification epic, workstream 4). This route stays only
// as a client-side redirect so old `/context` deep links keep resolving instead
// of 404-ing — required because static export (`output: export`) has no server
// to run next.config `redirects()`. Any incoming query params (scan, agent, …)
// are preserved on the way through.
function ContextRedirect() {
  const router = useRouter();
  const searchParams = useSearchParams();
  useEffect(() => {
    const params = new URLSearchParams(searchParams?.toString() ?? "");
    params.set("lens", "context");
    router.replace(`/graph?${params.toString()}`);
  }, [router, searchParams]);
  return (
    <div className="flex min-h-[40vh] items-center justify-center">
      <Loader2 className="h-6 w-6 animate-spin text-[var(--text-tertiary)]" />
    </div>
  );
}

export default function ContextRedirectPage() {
  return (
    <Suspense
      fallback={
        <div className="flex min-h-[40vh] items-center justify-center">
          <Loader2 className="h-6 w-6 animate-spin text-[var(--text-tertiary)]" />
        </div>
      }
    >
      <ContextRedirect />
    </Suspense>
  );
}
