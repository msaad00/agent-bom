"use client";

import { useState, type ChangeEvent } from "react";
import { FileText } from "lucide-react";
import type { ScanResult } from "@/lib/api";
import { checkFileSize, validateScanReport } from "@/lib/validators";

export function LocalReportImport({ onImport }: { onImport: (data: ScanResult) => void }) {
  const [importError, setImportError] = useState<string | null>(null);
  const handleFile = (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setImportError(null);

    const sizeCheck = checkFileSize(file);
    if (!sizeCheck.ok) {
      setImportError(sizeCheck.error);
      e.target.value = "";
      return;
    }

    const reader = new FileReader();
    reader.onerror = () => setImportError("Failed to read file.");
    reader.onload = (ev) => {
      const text = ev.target?.result;
      if (typeof text !== "string") {
        setImportError("Could not read file contents.");
        return;
      }
      const result = validateScanReport(text);
      if (!result.ok) {
        setImportError(result.error);
        return;
      }
      onImport(result.data as ScanResult);
    };
    reader.readAsText(file);
  };

  return (
          <div className="mt-6 rounded-2xl border border-dashed border-[var(--border-subtle)] bg-[var(--surface)]/40 p-6 text-center">
            <FileText className="mx-auto mb-3 h-8 w-8 text-[var(--text-tertiary)]" />
            <h3 className="text-sm font-semibold text-[var(--foreground)]">Preview a saved report</h3>
            <p className="mt-2 text-sm text-[var(--text-tertiary)]">
              Read a JSON report in this browser. This does not upload it to the control plane or populate its graph.
            </p>
            <code className="mt-4 block break-words [overflow-wrap:anywhere] rounded-xl border border-[var(--border-subtle)] bg-[var(--background)] px-4 py-3 font-mono text-xs leading-7 text-[var(--text-secondary)]">
              agent-bom scan --demo --offline -f json -o report.json
              <br />
              agent-bom scan . -f json -o report.json
            </code>
            {importError ? (
              <div className="mx-auto mt-4 max-w-xl rounded-xl border border-[color:var(--severity-critical-border)] bg-[color:var(--severity-critical-bg)] px-3 py-2 text-left">
                <p role="alert" className="break-words text-xs font-mono text-red-700 dark:text-red-300">{importError}</p>
              </div>
            ) : null}
            <label className="mt-5 inline-flex focus-within:outline-2 focus-within:outline-emerald-600 cursor-pointer items-center gap-2 rounded-lg border border-[var(--border-subtle)] bg-[var(--surface-elevated)] px-4 py-2 text-sm text-[var(--foreground)] transition-colors hover:bg-[var(--surface-muted)]">
              <FileText className="h-4 w-4" />
              Choose report.json
              <input
                type="file"
                accept=".json,application/json"
                className="sr-only"
                onChange={handleFile}
              />
            </label>
            <p className="mt-3 text-xs text-[var(--text-tertiary)]">Max 10 MB. Schema-validated before import.</p>
          </div>
  );
}
