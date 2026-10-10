"use client";

import { Collapsible } from "@/components/collapsible";
import {
  CLOUD_GRANT_METHODS,
  cloudGrantMethodHint,
  cloudGrantMethodLabel,
  copyTextToClipboard,
  type CloudGrantMethod
} from "@/lib/cloud-connect-wizard";
import {
  Copy
} from "lucide-react";
import { useState } from "react";



// ── Connect gallery ───────────────────────────────────────────────────────────

export function CopyTextButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      onClick={() => {
        void copyTextToClipboard(text).then((ok) => {
          if (!ok) return;
          setCopied(true);
          window.setTimeout(() => setCopied(false), 2000);
        });
      }}
      className="inline-flex items-center gap-1.5 rounded-lg border border-outline bg-surface-muted px-2.5 py-1 text-[11px] font-medium text-foreground transition hover:border-outline-strong"
    >
      <Copy className="h-3 w-3" />
      {copied ? "Copied" : label}
    </button>
  );
}


export function GrantMethodPicker({
  method,
  onChange,
  provider,
}: {
  method: CloudGrantMethod;
  onChange: (method: CloudGrantMethod) => void;
  provider: string;
}) {
  return (
    <div className="space-y-2">
      <div
        className="inline-flex rounded-lg border border-outline bg-surface-muted p-0.5"
        role="group"
        aria-label="Grant method"
      >
        {CLOUD_GRANT_METHODS.map((item) => (
          <button
            key={item}
            type="button"
            onClick={() => onChange(item)}
            className={`rounded-md px-2.5 py-1 text-[11px] font-medium transition ${
              method === item
                ? "bg-surface text-foreground shadow-sm"
                : "text-ink-tertiary hover:text-foreground"
            }`}
          >
            {cloudGrantMethodLabel(item)}
          </button>
        ))}
      </div>
      <p className="text-[10px] leading-4 text-ink-tertiary">{cloudGrantMethodHint(method, provider)}</p>
    </div>
  );
}


// Snowflake packaging: read-only metadata role (default) vs the Snowpark
// Container Services / Native App (run agent-bom inside the account).
export function SnowflakePackagingPicker({ spcs, onChange }: { spcs: boolean; onChange: (spcs: boolean) => void }) {
  return (
    <div
      role="group"
      aria-label="Snowflake packaging"
      className="grid grid-cols-2 gap-1 rounded-xl border border-outline bg-surface-muted p-1"
    >
      {[
        { value: false, label: "Read-only role", hint: "Metadata scan" },
        { value: true, label: "Native app (SPCS)", hint: "Runs in your account" },
      ].map((option) => {
        const active = spcs === option.value;
        return (
          <button
            key={option.label}
            type="button"
            aria-pressed={active}
            onClick={() => onChange(option.value)}
            className={`rounded-lg px-2.5 py-1.5 text-left transition ${
              active ? "bg-emerald-500 text-black" : "text-ink-secondary hover:text-foreground"
            }`}
          >
            <span className="block text-[11px] font-medium">{option.label}</span>
            <span className={`block text-[10px] ${active ? "text-black/70" : "text-ink-tertiary"}`}>
              {option.hint}
            </span>
          </button>
        );
      })}
    </div>
  );
}


// Connect depth (progressive disclosure, collapsed by default): baseline stays
// least-privilege; deep-scan + DSPM are explicit read-only opt-ins.
export function ConnectDepthControl({
  provider,
  deepScan,
  onDeepScanChange,
  dspmBucketsText,
  onDspmBucketsChange,
}: {
  provider: string;
  deepScan: boolean;
  onDeepScanChange: (value: boolean) => void;
  dspmBucketsText: string;
  onDspmBucketsChange: (value: string) => void;
}) {
  const grantsNote =
    provider === "aws"
      ? "Adds read-only Lambda code, ECR image, Inspector, CIS-contact & Bedrock-agent reads."
      : provider === "azure"
        ? "Adds read-only Key Vault Reader (CIS 8.1/8.2) & AcrPull (image SBOM)."
        : "Adds read-only Artifact Registry reader (image SBOM).";
  return (
    <Collapsible
      title="Scan depth (advanced)"
      defaultOpen={false}
      bare
      className="mt-3"
      titleClassName="text-[11px] font-medium uppercase tracking-[0.14em] text-ink-tertiary"
    >
      <div className="mt-2 space-y-2.5">
        <label className="flex cursor-pointer items-start gap-2.5">
          <input
            type="checkbox"
            checked={deepScan}
            onChange={(event) => onDeepScanChange(event.target.checked)}
            className="mt-0.5 h-4 w-4 shrink-0 accent-emerald-500"
            data-testid="wizard-deep-scan"
          />
          <span className="min-w-0">
            <span className="block text-xs font-medium text-foreground">Deep-scan content reads (read-only)</span>
            <span className="mt-0.5 block text-[11px] text-ink-secondary">{grantsNote}</span>
          </span>
        </label>
        {provider === "aws" ? (
          <label className="block">
            <span className="mb-1 block text-[11px] font-medium text-foreground">
              DSPM object sampling — S3 bucket ARNs (optional)
            </span>
            <input
              value={dspmBucketsText}
              onChange={(event) => onDspmBucketsChange(event.target.value)}
              placeholder="arn:aws:s3:::my-data-lake, arn:aws:s3:::logs"
              data-testid="wizard-dspm-buckets"
              className="w-full rounded-lg border border-outline bg-surface-elevated px-3 py-2 font-mono text-[11px] text-foreground outline-none transition focus:border-emerald-500"
            />
            <span className="mt-1 block text-[10px] text-ink-tertiary">
              Grants read-only s3:GetObject/ListBucket scoped to these buckets only. Implies deep-scan. Leave empty to
              disable object reads.
            </span>
          </label>
        ) : null}
      </div>
    </Collapsible>
  );
}
