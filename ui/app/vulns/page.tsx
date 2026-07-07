"use client";

import { Suspense, useEffect } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { Loader2 } from "lucide-react";

// `/vulns` was an unlinked duplicate of the Findings surface. It now redirects
// to the canonical `/findings` route, preserving any query params (scan, cve,
// severity, group, …) so existing deep links keep working.
function VulnsRedirect() {
  const router = useRouter();
  const searchParams = useSearchParams();
  useEffect(() => {
    const qs = searchParams.toString();
    router.replace(qs ? `/findings?${qs}` : "/findings");
  }, [router, searchParams]);
  return (
    <div className="flex min-h-[40vh] items-center justify-center">
      <Loader2 className="h-6 w-6 animate-spin text-zinc-500" />
    </div>
  );
}

export default function VulnsRedirectPage() {
  return (
    <Suspense
      fallback={
        <div className="flex min-h-[40vh] items-center justify-center">
          <Loader2 className="h-6 w-6 animate-spin text-zinc-500" />
        </div>
      }
    >
      <VulnsRedirect />
    </Suspense>
  );
}
