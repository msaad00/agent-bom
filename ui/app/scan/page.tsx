"use client";

/**
 * Scan page — slim router that delegates to extracted components.
 * Previously 1,944 lines; now ~30 lines.
 */

import { Suspense } from "react";
import { useSearchParams } from "next/navigation";
import { Loader2 } from "lucide-react";
import { ScanForm } from "@/components/scan-form";
import { ScanResultView } from "@/components/scan-result";
import { AttackFlowView } from "@/components/attack-flow";
import { ScanMeshView } from "@/components/scan-mesh";

function ScanRouter() {
  const searchParams = useSearchParams();
  const id = searchParams.get("id") || "";
  const view = searchParams.get("view") || "";

  if (id && view === "attack-flow") return <AttackFlowView id={id} />;
  if (id && view === "mesh") return <ScanMeshView id={id} />;
  if (id) return <ScanResultView id={id} />;
  return <ScanForm />;
}

export default function ScanPage() {
  return (
    <Suspense
      fallback={
        <div className="flex items-center justify-center h-[50vh] text-zinc-400">
          <Loader2 className="w-5 h-5 animate-spin mr-2" />Loading...
        </div>
      }
    >
      <ScanRouter />
    </Suspense>
  );
}
