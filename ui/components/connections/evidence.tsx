"use client";

import { EvidenceFields } from "@/components/evidence-fields";

import { evidenceLinks } from "@/components/connections/display";
import {
  type CloudConnectionRecord,
  type CloudConnectionScanResponse
} from "@/lib/api";
import {
  FileSearch,
  Loader2
} from "lucide-react";
import Link from "next/link";


export function ConnectionEvidenceSummary({ connection }: { connection: CloudConnectionRecord }) {
  const mode = connection.auth_params?.auth_mode;
  const recordedCredential = connection.credential_present || connection.has_external_id;
  const authentication = connection.provider === "azure" && mode === "managed_identity" ? "Managed identity"
    : connection.provider === "snowflake" && mode === "workload_identity" ? "Native App workload identity"
    : ["azure", "gcp"].includes(connection.provider) && mode === "workload_identity" ? "Workload identity"
    : mode ? "Unrecognized authentication mode"
    : !recordedCredential ? "Not recorded"
    : connection.provider === "aws" ? "AWS AssumeRole"
    : connection.provider === "azure" ? "Client secret (legacy)"
    : connection.provider === "gcp" ? "Service-account key (legacy)"
    : connection.provider === "snowflake" ? "Key-pair authentication"
    : "Not recorded";
  const scope = connection.inventory_scope === "organization" ? "Organization"
    : connection.inventory_scope === "account" ? "Account" : "Unavailable";
  const cadence = connection.scan_interval_minutes === null ? "Manual"
    : typeof connection.scan_interval_minutes === "number" && connection.scan_interval_minutes > 0
      ? `Every ${connection.scan_interval_minutes} minutes` : "Unavailable";
  const fields = [
    ["Authentication", authentication], ["Inventory scope", scope],
    ["Regions", connection.regions?.length ? connection.regions.join(", ") : "Not recorded"],
    ["Scan schedule", cadence],
  ];
  const probeStatus = connection.capability_probe_status?.replaceAll("_", " ") ?? "Unavailable";
  return (
    <section aria-label="Recorded connection configuration" className="space-y-3">
      <EvidenceFields label="Connection settings" fields={fields.map(([label, value]) => ({ label: label!, value }))} />
      <details className="border-y border-outline py-2 text-sm">
        <summary className="cursor-pointer font-medium">Capability evidence</summary>
        <EvidenceFields label="Capability evidence details" className="mt-3" fields={[
          { label: "Last probe", value: probeStatus },
          { label: "Verification time", value: "Unavailable" },
          { label: "Verified reads", value: connection.verified_capabilities?.length ? connection.verified_capabilities.join(", ") : "None recorded", wide: true },
          { label: "Collection gaps", value: "Not reported by this connection record", wide: true },
        ]} />
        <p className="mt-2 text-xs text-ink-secondary">Configuration does not establish read access. Open the scan result for collection coverage and failures.</p>
      </details>
    </section>
  );
}


export function ScanResultPanel({ result }: { result: CloudConnectionScanResponse }) {
  return (
    <div className="rounded-xl border border-outline bg-surface p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="inline-flex items-center gap-2 text-xs font-semibold text-foreground">
          <Loader2 className="h-4 w-4 animate-spin text-sky-400" />
          Read-only scan queued
        </p>
        <span className="font-mono text-[10px] text-ink-tertiary">job {result.job_id.slice(0, 8)}</span>
      </div>
      <p className="mt-3 text-[11px] leading-5 text-ink-tertiary">
        The durable worker will broker the stored read-only credential and persist inventory, CIS evidence, findings,
        and graph data. The job page reports progress and sanitized failures.
      </p>
      <div className="mt-4 flex flex-wrap gap-2">
        {evidenceLinks(result.job_id).slice(0, 2).map(({ label, href, icon: Icon }) => (
          <HandoffLink key={label} label={label} href={href} icon={Icon} />
        ))}
      </div>
    </div>
  );
}


export function ScanHandoffLinks({ scanId }: { scanId: string }) {
  return (
    <div className="rounded-xl border border-outline bg-surface p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="inline-flex items-center gap-2 text-xs font-semibold text-foreground">
          <FileSearch className="h-4 w-4 text-emerald-400" />
          Last scan handoff
        </p>
        <span className="font-mono text-[10px] text-ink-tertiary">scan {scanId.slice(0, 8)}</span>
      </div>
      <div className="mt-3 flex flex-wrap gap-2">
        {evidenceLinks(scanId).map(({ label, href, icon }) => (
          <HandoffLink key={label} label={label} href={href} icon={icon} />
        ))}
      </div>
    </div>
  );
}


export function HandoffLink({
  label,
  href,
  icon: Icon,
}: {
  label: string;
  href: string;
  icon: React.ComponentType<{ className?: string }>;
}) {
  return (
    <Link
      href={href}
      className="inline-flex items-center gap-1.5 rounded-lg border border-outline bg-surface-elevated px-2.5 py-1.5 text-[11px] font-medium text-foreground transition hover:border-emerald-700 hover:text-emerald-700 dark:hover:text-emerald-300"
    >
      <Icon className="h-3.5 w-3.5" />
      {label}
    </Link>
  );
}
