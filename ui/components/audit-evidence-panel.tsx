"use client";

import { useState } from "react";
import {
  Download,
  FileCheck2,
  Loader2,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";

import {
  api,
  type AuditExportPacket,
  type AuditExportVerifyResult,
} from "@/lib/api";
import { userFacingApiErrorMessage } from "@/lib/api-errors";

type VerifyState = {
  result: AuditExportVerifyResult;
  /** Round-trip verification of a freshly-exported packet vs. a pasted one. */
  source: "export" | "paste";
  tamperedEntries: number;
};

function reportedTamperedEntries(payload: unknown): number {
  if (!payload || typeof payload !== "object") return 0;
  const integrity = (payload as { integrity?: unknown }).integrity;
  if (!integrity || typeof integrity !== "object") return 0;
  const value = (integrity as { tampered?: unknown }).tampered;
  return typeof value === "number" && Number.isFinite(value) && value > 0 ? value : 0;
}

function downloadPacket(packet: AuditExportPacket): void {
  if (typeof window === "undefined" || typeof URL.createObjectURL !== "function") {
    return;
  }
  const blob = new Blob([JSON.stringify(packet, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = "agent-bom-audit-export.json";
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

/** Extract a `{ payload, signature }` packet from a pasted export blob. */
function parsePacket(raw: string, signatureField: string): AuditExportPacket | { error: string } {
  const trimmed = raw.trim();
  if (!trimmed) return { error: "Paste an exported audit packet to verify." };
  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    // Not JSON — treat the raw text as the payload, needs an explicit signature.
    if (!signatureField.trim()) return { error: "Add the export signature to verify raw text." };
    return { payload: trimmed, signature: signatureField.trim() };
  }
  if (
    parsed &&
    typeof parsed === "object" &&
    "payload" in parsed &&
    "signature" in parsed &&
    typeof (parsed as { signature: unknown }).signature === "string"
  ) {
    const wrapper = parsed as { payload: unknown; signature: string };
    return { payload: wrapper.payload, signature: wrapper.signature };
  }
  if (!signatureField.trim()) {
    return { error: "This looks like a bare export body — add its signature to verify." };
  }
  return { payload: parsed, signature: signatureField.trim() };
}

/**
 * Human UI for the signed audit evidence surface (P1-2, #4014): download a
 * tamper-evident export and verify one round-trip (PASS/FAIL) — GRC evidence
 * that the log has not been altered, without exposing HMAC key material.
 */
export function AuditEvidencePanel() {
  const [exporting, setExporting] = useState(false);
  const [lastExport, setLastExport] = useState<AuditExportPacket | null>(null);
  const [exportError, setExportError] = useState<string | null>(null);

  const [pasteValue, setPasteValue] = useState("");
  const [signatureValue, setSignatureValue] = useState("");
  const [verifying, setVerifying] = useState(false);
  const [verifyError, setVerifyError] = useState<string | null>(null);
  const [verifyState, setVerifyState] = useState<VerifyState | null>(null);

  async function runExport() {
    setExporting(true);
    setExportError(null);
    try {
      const packet = await api.exportAuditPacket();
      setLastExport(packet);
      downloadPacket(packet);
      // Round-trip: prove the freshly-signed packet verifies clean.
      const result = await api.verifyAuditPacket(packet.payload, packet.signature);
      setVerifyState({
        result,
        source: "export",
        tamperedEntries: reportedTamperedEntries(packet.payload),
      });
      setVerifyError(null);
    } catch (err) {
      setExportError(userFacingApiErrorMessage(err, "Audit export failed"));
    } finally {
      setExporting(false);
    }
  }

  async function runVerify() {
    const packet = parsePacket(pasteValue, signatureValue);
    if ("error" in packet) {
      setVerifyError(packet.error);
      setVerifyState(null);
      return;
    }
    setVerifying(true);
    setVerifyError(null);
    try {
      const result = await api.verifyAuditPacket(packet.payload, packet.signature);
      setVerifyState({
        result,
        source: "paste",
        tamperedEntries: reportedTamperedEntries(packet.payload),
      });
    } catch (err) {
      setVerifyState(null);
      setVerifyError(userFacingApiErrorMessage(err, "Audit verification failed"));
    } finally {
      setVerifying(false);
    }
  }

  return (
    <section
      aria-label="Audit evidence export and verification"
      className="grid gap-3 md:grid-cols-2"
    >
      {/* Export */}
      <div className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-4">
        <div className="flex items-center gap-2">
          <Download className="h-4 w-4 text-[color:var(--accent)]" aria-hidden="true" />
          <h2 className="text-sm font-semibold text-[color:var(--foreground)]">Export signed evidence</h2>
        </div>
        <p className="mt-1 text-xs text-[color:var(--text-tertiary)]">
          Download a JSON evidence packet with its detached HMAC signature for auditors.
        </p>
        <button
          type="button"
          onClick={() => void runExport()}
          disabled={exporting}
          className="mt-3 inline-flex items-center gap-2 rounded-lg border border-[color:var(--accent-border)] bg-[color:var(--accent-soft)] px-3 py-2 text-sm font-medium text-[color:var(--accent)] transition hover:bg-[color:var(--accent-soft-hover)] disabled:cursor-not-allowed disabled:opacity-50"
        >
          {exporting ? (
            <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
          ) : (
            <Download className="h-4 w-4" aria-hidden="true" />
          )}
          Export &amp; verify
        </button>

        {exportError && (
          <p
            role="alert"
            className="mt-3 rounded-lg border border-[color:var(--status-danger-border)] bg-[color:var(--status-danger-bg)] px-3 py-2 text-xs text-[color:var(--status-danger)]"
          >
            {exportError}
          </p>
        )}

        {lastExport && !exportError && (
          <div className="mt-3 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-2 text-xs">
            <div className="text-[10px] uppercase tracking-[0.16em] text-[color:var(--text-tertiary)]">
              Signature
            </div>
            <code className="mt-0.5 block truncate font-mono text-[11px] text-[color:var(--text-secondary)]">
              {lastExport.signature ? `${lastExport.signature.slice(0, 32)}…` : "not provided by server"}
            </code>
          </div>
        )}
      </div>

      {/* Verify */}
      <div className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-4">
        <div className="flex items-center gap-2">
          <FileCheck2 className="h-4 w-4 text-[color:var(--accent)]" aria-hidden="true" />
          <h2 className="text-sm font-semibold text-[color:var(--foreground)]">Verify an export</h2>
        </div>
        <p className="mt-1 text-xs text-[color:var(--text-tertiary)]">
          Paste an exported packet to confirm the log is tamper-evident and unaltered.
        </p>

        <label htmlFor="audit-verify-packet" className="sr-only">
          Exported audit packet
        </label>
        <textarea
          id="audit-verify-packet"
          value={pasteValue}
          onChange={(event) => setPasteValue(event.target.value)}
          rows={4}
          placeholder='{"payload": …, "signature": "…"}'
          className="mt-2 w-full resize-y rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-2 font-mono text-[11px] text-[color:var(--foreground)] placeholder-[color:var(--text-tertiary)] focus:border-[color:var(--accent-border)] focus:outline-none"
        />
        <label htmlFor="audit-verify-signature" className="sr-only">
          Signature (only needed for a bare export body)
        </label>
        <input
          id="audit-verify-signature"
          value={signatureValue}
          onChange={(event) => setSignatureValue(event.target.value)}
          placeholder="Signature (optional — only for a bare export body)"
          className="mt-2 w-full rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-2 font-mono text-[11px] text-[color:var(--foreground)] placeholder-[color:var(--text-tertiary)] focus:border-[color:var(--accent-border)] focus:outline-none"
        />
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => void runVerify()}
            disabled={verifying}
            className="inline-flex items-center gap-2 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-2 text-sm font-medium text-[color:var(--text-secondary)] transition hover:border-[color:var(--border-strong)] hover:text-[color:var(--foreground)] disabled:cursor-not-allowed disabled:opacity-50"
          >
            {verifying ? (
              <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
            ) : (
              <ShieldCheck className="h-4 w-4" aria-hidden="true" />
            )}
            Verify
          </button>
          {lastExport && (
            <button
              type="button"
              onClick={() => {
                setPasteValue(JSON.stringify(lastExport, null, 2));
                setSignatureValue("");
                setVerifyError(null);
              }}
              className="text-xs text-[color:var(--accent)] underline-offset-2 hover:underline"
            >
              Fill from last export
            </button>
          )}
        </div>

        {verifyError && (
          <p
            role="alert"
            className="mt-3 rounded-lg border border-[color:var(--status-danger-border)] bg-[color:var(--status-danger-bg)] px-3 py-2 text-xs text-[color:var(--status-danger)]"
          >
            {verifyError}
          </p>
        )}

        {verifyState && !verifyError && (() => {
          const verifiedIntact = verifyState.result.valid && verifyState.tamperedEntries === 0;
          return (
          <div
            data-testid="audit-verify-result"
            data-valid={verifiedIntact ? "true" : "false"}
            className={`mt-3 flex items-start gap-3 rounded-lg border px-3 py-2.5 ${
              verifiedIntact
                ? "border-[color:var(--status-success-border)] bg-[color:var(--status-success-bg)]"
                : "border-[color:var(--status-danger-border)] bg-[color:var(--status-danger-bg)]"
            }`}
          >
            {verifiedIntact ? (
              <ShieldCheck
                className="mt-0.5 h-5 w-5 shrink-0 text-[color:var(--status-success)]"
                aria-hidden="true"
              />
            ) : (
              <ShieldAlert
                className="mt-0.5 h-5 w-5 shrink-0 text-[color:var(--status-danger)]"
                aria-hidden="true"
              />
            )}
            <div className="min-w-0">
              <div
                className={`text-sm font-bold tracking-[0.12em] ${
                  verifiedIntact
                    ? "text-[color:var(--status-success)]"
                    : "text-[color:var(--status-danger)]"
                }`}
              >
                {verifiedIntact ? "PASS" : "FAIL"}
              </div>
              <p className="mt-0.5 text-xs text-[color:var(--text-secondary)]">
                {verifiedIntact
                  ? "Signature matches — the exported log is intact and tamper-evident."
                  : verifyState.result.valid
                    ? `Signature matches, but the payload reports tampered entries (${verifyState.tamperedEntries}).`
                    : "Signature mismatch — the packet has been altered or the signature is wrong."}
                {verifyState.source === "export" ? " (fresh export round-trip)" : ""}
              </p>
              <p className="mt-0.5 text-[10px] text-[color:var(--text-tertiary)]">
                {verifyState.result.payload_bytes.toLocaleString()} bytes verified
              </p>
            </div>
          </div>
          );
        })()}
      </div>
    </section>
  );
}
