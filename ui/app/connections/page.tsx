"use client";

import { ConnectionsHub } from "@/components/connections/hub";
import { PageLoadingState } from "@/components/states/page-loading-state";
import { Suspense } from "react";


// ── Page shell (Suspense boundary for useSearchParams) ────────────────────────

export default function ConnectionsPage() {
  return (
    <Suspense
      fallback={
        <PageLoadingState compact title="Loading connections" detail="Preparing connection workflows" />
      }
    >
      <ConnectionsHub />
    </Suspense>
  );
}
