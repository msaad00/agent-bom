import type { CloudConnectionRecord, ScanRequest } from "@/lib/api";

export type ScanMode = "connected" | "adhoc" | "scheduled";

export type AdhocScanTarget = "workstation" | "containers" | "kubernetes" | "repository";

export type ScanScopeChip = {
  label: string;
  value: string;
};

const SCANNABLE_PROVIDERS = new Set(["aws", "azure", "gcp", "snowflake"]);

const PROVIDER_LABELS: Record<string, string> = {
  aws: "AWS",
  azure: "Azure",
  gcp: "GCP",
  snowflake: "Snowflake",
};

export function providerDisplayName(provider: string): string {
  const key = provider.trim().toLowerCase();
  return PROVIDER_LABELS[key] ?? provider.toUpperCase();
}

export function isScannableConnection(connection: CloudConnectionRecord): boolean {
  return SCANNABLE_PROVIDERS.has(String(connection.provider ?? "").trim().toLowerCase());
}

export function cloudAccountBoundary(connection: CloudConnectionRecord): string {
  const provider = String(connection.provider ?? "").trim().toLowerCase();
  const params = connection.auth_params ?? {};

  switch (provider) {
    case "aws":
      return connection.role_ref || "Assumed IAM role";
    case "azure":
      return params.subscription_id
        ? `Subscription ${params.subscription_id}`
        : "Azure subscription";
    case "gcp":
      return params.project_id ? `Project ${params.project_id}` : "GCP project";
    case "snowflake":
      return params.account ? `Account ${params.account}` : "Snowflake account";
    default:
      return connection.display_name;
  }
}

export function cloudRegionScope(connection: CloudConnectionRecord): string {
  if (connection.regions.length === 0) {
    return "Provider default region";
  }
  if (connection.regions.length === 1) {
    return connection.regions[0] ?? "Provider default region";
  }
  return `${connection.regions.length} regions (${connection.regions.slice(0, 2).join(", ")}${connection.regions.length > 2 ? ", …" : ""})`;
}

export function cloudConnectionScopeChips(connection: CloudConnectionRecord): ScanScopeChip[] {
  const chips: ScanScopeChip[] = [
    { label: "Provider", value: providerDisplayName(connection.provider) },
    { label: "Account", value: connection.display_name },
    { label: "Boundary", value: cloudAccountBoundary(connection) },
    { label: "Regions", value: cloudRegionScope(connection) },
    { label: "Scan type", value: "Read-only inventory + CIS" },
  ];

  if (connection.scan_interval_minutes) {
    chips.push({
      label: "Schedule",
      value: `Every ${connection.scan_interval_minutes} min`,
    });
  } else {
    chips.push({ label: "Schedule", value: "Manual on demand" });
  }

  return chips;
}

export function adhocScopeChips(
  form: ScanRequest,
  target: AdhocScanTarget,
): ScanScopeChip[] {
  const chips: ScanScopeChip[] = [];

  if (target === "repository" && form.repo_url?.trim()) {
    chips.push(
      { label: "Repository", value: form.repo_url.trim() },
      { label: "Clone", value: "Shallow read-only git clone on control plane" },
      { label: "Execution", value: "Static parse only — repo code never runs" },
      { label: "Auto-detect", value: "Agents · MCP · Skills · Terraform · IaC · CI/CD · deps · notebooks · secrets · crypto · SAST*" },
      { label: "Lockfiles", value: "uv.lock · requirements.txt · poetry.lock · package-lock.json · go.sum · …" },
      { label: "Not in repo URL", value: "SaaS connectors (Jira/Slack/…) — use Data Sources or Cloud Accounts" },
      { label: "Languages", value: "Python · TS/JS · YAML · HCL · Markdown · lockfiles" },
    );
    if (form.enrich) {
      chips.push({ label: "Enrichment", value: "NVD · EPSS · CISA KEV" });
    }
    return chips;
  }

  chips.push({
    label: "Baseline",
    value: "Local MCP configs on control plane host",
  });

  const projects = form.agent_projects ?? [];
  const images = form.images ?? [];
  const tfDirs = form.tf_dirs ?? [];

  if (target === "workstation" || projects.length > 0) {
    chips.push({
      label: "Agent projects",
      value:
        projects.length > 0
          ? `${projects.length} path${projects.length === 1 ? "" : "s"}`
          : "None queued — baseline discovery only",
    });
  }

  if (target === "containers" || images.length > 0) {
    chips.push({
      label: "Container images",
      value: images.length > 0 ? `${images.length} image${images.length === 1 ? "" : "s"}` : "None queued",
    });
  }

  if (target === "kubernetes" || form.k8s) {
    chips.push({
      label: "Kubernetes",
      value: form.k8s
        ? form.k8s_namespace?.trim()
          ? `Namespace ${form.k8s_namespace.trim()}`
          : "All namespaces in current kube context"
        : "Not enabled",
    });
  }

  if (tfDirs.length > 0) {
    chips.push({
      label: "Terraform",
      value: `${tfDirs.length} director${tfDirs.length === 1 ? "y" : "ies"}`,
    });
  }

  if (form.gha_path?.trim()) {
    chips.push({ label: "GitHub Actions", value: form.gha_path.trim() });
  }

  if (form.inventory?.trim()) {
    chips.push({ label: "Inventory file", value: form.inventory.trim() });
  }

  if (form.enrich) {
    chips.push({ label: "Enrichment", value: "NVD · EPSS · CISA KEV" });
  }

  return chips;
}

export function scheduledSourceScopeChips(source: {
  display_name: string;
  kind: string;
  last_run_at: string | null;
  enabled: boolean;
}): ScanScopeChip[] {
  return [
    { label: "Source", value: source.display_name },
    { label: "Kind", value: source.kind.replace(/\./g, " · ") },
    {
      label: "Status",
      value: source.enabled ? "Enabled" : "Disabled",
    },
    {
      label: "Last run",
      value: source.last_run_at ? "Previously executed" : "Not run yet",
    },
  ];
}
