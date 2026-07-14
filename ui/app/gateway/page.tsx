"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { Loader2 } from "lucide-react";

// The gateway dashboard is embedded inside the unified Runtime surface
// (`/runtime?tab=gateway`). This standalone route stays only as a canonical
// redirect so old links resolve to the single enforcement surface instead of
// an orphan duplicate destination. The dashboard component lives in
// ./GatewayDashboard and is rendered by /runtime.
export default function GatewayRedirect() {
  const router = useRouter();
  useEffect(() => {
    router.replace("/runtime?tab=gateway");
  }, [router]);
  return (
    <div className="flex min-h-[40vh] items-center justify-center">
      <Loader2 className="h-6 w-6 animate-spin text-[var(--text-tertiary)]" />
    </div>
  );
}
