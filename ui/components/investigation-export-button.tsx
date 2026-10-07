"use client";

import { Download } from "lucide-react";
import type { ExposurePath } from "@/lib/exposure-path";
import { investigationExport } from "@/lib/investigation-export";

export function InvestigationExportButton({ path, scanId }: { path: ExposurePath | null; scanId: string }) {
  return <button type="button" className="sg-action" disabled={!path || !scanId} onClick={() => {
    if (!path) return;
    const evidence = investigationExport(path, scanId, `${window.location.pathname}${window.location.search}`);
    const url = URL.createObjectURL(new Blob([JSON.stringify(evidence, null, 2)], { type: "application/json" }));
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = "agent-bom-selected-path.json";
    anchor.click();
    URL.revokeObjectURL(url);
  }}><Download className="h-4 w-4" aria-hidden="true" />Export selected path</button>;
}
