"use client";

import { Suspense, useEffect } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { Loader2 } from "lucide-react";

// The Agent Mesh lens lives on the canonical `/security-graph` investigation
// surface, selected with `?lens=mesh`. This route stays only as
// a client-side redirect so old `/mesh` deep links keep resolving instead of
// 404-ing — required because static export (`output: export`) has no server to
// run next.config `redirects()`. Any incoming query params (scan, agent, cve,
// severity, …) are preserved on the way through.
function MeshRedirect() {
  const router = useRouter();
  const searchParams = useSearchParams();
  useEffect(() => {
    const params = new URLSearchParams(searchParams?.toString() ?? "");
    params.set("lens", "mesh");
    router.replace(`/security-graph?${params.toString()}`);
  }, [router, searchParams]);
  return (
    <div className="flex min-h-[40vh] items-center justify-center">
      <Loader2 className="h-6 w-6 animate-spin text-[var(--text-tertiary)]" />
    </div>
  );
}

export default function MeshRedirectPage() {
  return (
    <Suspense
      fallback={
        <div className="flex min-h-[40vh] items-center justify-center">
          <Loader2 className="h-6 w-6 animate-spin text-[var(--text-tertiary)]" />
        </div>
      }
    >
      <MeshRedirect />
    </Suspense>
  );
}
