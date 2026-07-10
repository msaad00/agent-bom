export type CloudProviderId = "aws" | "azure" | "gcp" | "snowflake";

/** How the operator mints the read-only grant — pick what their rights allow. */
export type CloudGrantMethod = "cli" | "cloudshell" | "terraform";

export const CLOUD_GRANT_METHODS: CloudGrantMethod[] = ["cli", "cloudshell", "terraform"];

export type CloudProviderMeta = {
  terraformModule: string;
  provisionScript: string;
  inventoryEnv: string;
  scanSurfaces: string[];
  deployNotes: string[];
  /** Vendor shell product name for CloudShell framing. */
  cloudShellLabel: string;
};

export const CLOUD_PROVIDER_META: Record<CloudProviderId, CloudProviderMeta> = {
  aws: {
    terraformModule: "deploy/terraform/connect-aws",
    provisionScript: "scripts/provision/aws_readonly_policy.json",
    inventoryEnv: "AGENT_BOM_AWS_INVENTORY",
    scanSurfaces: ["Inventory", "CIS", "Identities", "AI workloads"],
    deployNotes: [
      "Read-only IAM only — SecurityAudit / ViewOnly class permissions.",
      "Prefer an ExternalId on the trust policy (generate in the wizard).",
      "Pick CLI, CloudShell, or Terraform based on who can change IAM in your org.",
    ],
    cloudShellLabel: "AWS CloudShell",
  },
  azure: {
    terraformModule: "deploy/terraform/connect-azure",
    provisionScript: "scripts/provision/azure_readonly_role.json",
    inventoryEnv: "AGENT_BOM_AZURE_INVENTORY",
    scanSurfaces: ["Inventory", "CIS", "Entra", "Managed AI"],
    deployNotes: [
      "Mints a Reader / Security Reader principal — no write roles.",
      "Store the client secret once — the control plane encrypts it at rest.",
      "Azure Cloud Shell works when you cannot run Terraform locally.",
    ],
    cloudShellLabel: "Azure Cloud Shell",
  },
  gcp: {
    terraformModule: "deploy/terraform/connect-gcp",
    provisionScript: "scripts/provision/gcp_readonly_role.yaml",
    inventoryEnv: "AGENT_BOM_GCP_INVENTORY",
    scanSurfaces: ["Inventory", "CIS", "IAM", "Vertex AI"],
    deployNotes: [
      "Creates a Viewer + Security Reviewer service account (read-only).",
      "Paste the key JSON only in the final wizard step.",
      "Google Cloud Shell is fine when local gcloud/Terraform is blocked.",
    ],
    cloudShellLabel: "Google Cloud Shell",
  },
  snowflake: {
    terraformModule: "deploy/terraform/connect-snowflake",
    provisionScript: "scripts/provision/snowflake_readonly.sql",
    inventoryEnv: "SNOWFLAKE_ACCOUNT",
    scanSurfaces: ["Governance", "Agents", "Activity", "Warehouses"],
    deployNotes: [
      "Provisions a read-only role + key-pair user (ACCOUNTADMIN once).",
      "Use the generated PEM private key in the wizard secret field.",
      "SQL worksheet / SnowSQL is the CloudShell equivalent for Snowflake.",
    ],
    cloudShellLabel: "Snowsight SQL worksheet",
  },
};

export function cloudProviderMeta(provider: string): CloudProviderMeta | null {
  if (provider in CLOUD_PROVIDER_META) {
    return CLOUD_PROVIDER_META[provider as CloudProviderId];
  }
  return null;
}

export function cloudGrantMethodLabel(method: CloudGrantMethod): string {
  switch (method) {
    case "cli":
      return "CLI";
    case "cloudshell":
      return "CloudShell";
    case "terraform":
      return "Terraform";
  }
}

export function cloudGrantMethodHint(method: CloudGrantMethod, provider: string): string {
  const meta = cloudProviderMeta(provider);
  switch (method) {
    case "cli":
      return "Local aws / az / gcloud / snow CLI — when you already have cloud admin tooling.";
    case "cloudshell":
      return meta
        ? `Paste into ${meta.cloudShellLabel} — no local Terraform install required.`
        : "Paste into the vendor cloud shell / console.";
    case "terraform":
      return "IaC path — best when platform/SRE owns apply rights and wants reviewable state.";
  }
}

function grantFooter(provider: string, inventoryEnv: string): string[] {
  return [
    "",
    "# After the grant exists, register it in the control plane wizard (role ARN / SP / SA / user).",
    `# Optional local smoke:`,
    `export ${inventoryEnv}=1`,
    `agent-bom connect ${provider}`,
  ];
}

/** Terraform module apply — for operators with IaC rights. */
export function buildTerraformDeployScript(provider: string): string {
  const meta = cloudProviderMeta(provider);
  if (!meta) return "";
  const terraformModule = meta.terraformModule;
  return [
    `# ${provider} read-only connector for agent-bom (Terraform)`,
    `terraform -chdir=${terraformModule} init`,
    `terraform -chdir=${terraformModule} apply`,
    "",
    "# After apply, read outputs for role/account references:",
    `terraform -chdir=${terraformModule} output`,
    ...grantFooter(provider, meta.inventoryEnv),
  ].join("\n");
}

/**
 * Cloud CLI grant recipes (aws / az / gcloud / snow).
 * Aligned with scripts/provision — operators paste and adapt ACCOUNT/PROJECT IDs.
 */
export function buildCliGrantScript(provider: string, externalId?: string): string {
  const meta = cloudProviderMeta(provider);
  if (!meta) return "";
  const eid = (externalId ?? "").trim() || "<EXTERNAL_ID>";

  switch (provider) {
    case "aws":
      return [
        `# AWS read-only grant for agent-bom (CLI)`,
        `# Requires IAM permissions to create roles/policies. Prefer ExternalId trust.`,
        `ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)`,
        `EXTERNAL_ID=${eid}`,
        "",
        `aws iam create-policy \\`,
        `  --policy-name agent-bom-readonly \\`,
        `  --policy-document file://${meta.provisionScript}`,
        "",
        `cat > /tmp/agent-bom-trust.json <<EOF`,
        `{`,
        `  "Version": "2012-10-17",`,
        `  "Statement": [{`,
        `    "Effect": "Allow",`,
        `    "Principal": { "AWS": "arn:aws:iam::\${ACCOUNT_ID}:root" },`,
        `    "Action": "sts:AssumeRole",`,
        `    "Condition": { "StringEquals": { "sts:ExternalId": "\${EXTERNAL_ID}" } }`,
        `  }]`,
        `}`,
        `EOF`,
        "",
        `aws iam create-role \\`,
        `  --role-name agent-bom-readonly \\`,
        `  --assume-role-policy-document file:///tmp/agent-bom-trust.json`,
        "",
        `aws iam attach-role-policy \\`,
        `  --role-name agent-bom-readonly \\`,
        `  --policy-arn arn:aws:iam::\${ACCOUNT_ID}:policy/agent-bom-readonly`,
        "",
        `# Also attach AWS managed SecurityAudit for broad read coverage:`,
        `aws iam attach-role-policy \\`,
        `  --role-name agent-bom-readonly \\`,
        `  --policy-arn arn:aws:iam::aws:policy/SecurityAudit`,
        "",
        `echo "Role ARN: arn:aws:iam::\${ACCOUNT_ID}:role/agent-bom-readonly"`,
        `echo "ExternalId: \${EXTERNAL_ID}"`,
        ...grantFooter(provider, meta.inventoryEnv),
      ].join("\n");

    case "azure":
      return [
        `# Azure read-only grant for agent-bom (Azure CLI)`,
        `SUBSCRIPTION_ID=$(az account show --query id -o tsv)`,
        "",
        `az ad sp create-for-rbac \\`,
        `  --name agent-bom-readonly \\`,
        `  --role Reader \\`,
        `  --scopes "/subscriptions/\${SUBSCRIPTION_ID}" \\`,
        `  --sdk-auth`,
        "",
        `# Optional: also assign Security Reader for posture APIs`,
        `# az role assignment create --assignee <appId> --role "Security Reader" --scope "/subscriptions/\${SUBSCRIPTION_ID}"`,
        "",
        `# Custom role definition (optional, tighter than Reader):`,
        `# az role definition create --role-definition ${meta.provisionScript}`,
        ...grantFooter(provider, meta.inventoryEnv),
      ].join("\n");

    case "gcp":
      return [
        `# GCP read-only grant for agent-bom (gcloud CLI)`,
        `PROJECT_ID=$(gcloud config get-value project)`,
        `SA_NAME=agent-bom-readonly`,
        `SA_EMAIL=\${SA_NAME}@\${PROJECT_ID}.iam.gserviceaccount.com`,
        "",
        `gcloud iam service-accounts create \${SA_NAME} \\`,
        `  --display-name="agent-bom read-only scanner"`,
        "",
        `gcloud projects add-iam-policy-binding \${PROJECT_ID} \\`,
        `  --member="serviceAccount:\${SA_EMAIL}" \\`,
        `  --role="roles/viewer"`,
        "",
        `gcloud projects add-iam-policy-binding \${PROJECT_ID} \\`,
        `  --member="serviceAccount:\${SA_EMAIL}" \\`,
        `  --role="roles/iam.securityReviewer"`,
        "",
        `gcloud iam service-accounts keys create ./agent-bom-sa.json \\`,
        `  --iam-account="\${SA_EMAIL}"`,
        "",
        `# Optional custom role: gcloud iam roles create … --file=${meta.provisionScript}`,
        ...grantFooter(provider, meta.inventoryEnv),
      ].join("\n");

    case "snowflake":
      return [
        `# Snowflake read-only grant for agent-bom (SnowSQL / snow CLI)`,
        `# Requires ACCOUNTADMIN (or equivalent) once.`,
        `snow sql -f ${meta.provisionScript}`,
        "",
        `# Or paste scripts/provision/snowflake_readonly.sql into a worksheet.`,
        `# Then register the role/user + private key in the control plane wizard.`,
        ...grantFooter(provider, meta.inventoryEnv),
      ].join("\n");

    default:
      return "";
  }
}

/**
 * Same grant as CLI, framed for paste into the vendor CloudShell / console.
 * No local Terraform; uses the cloud's browser shell.
 */
export function buildCloudShellGrantScript(provider: string, externalId?: string): string {
  const meta = cloudProviderMeta(provider);
  if (!meta) return "";
  const cli = buildCliGrantScript(provider, externalId);
  const header = [
    `# ${provider} read-only grant for agent-bom — paste into ${meta.cloudShellLabel}`,
    `# Open ${meta.cloudShellLabel} in the cloud console, then paste below.`,
    `# No local Terraform or laptop tooling required.`,
    "",
  ].join("\n");
  // Strip the first CLI title line so we don't double-header.
  const body = cli.split("\n").slice(1).join("\n");
  return `${header}${body}`;
}

export function buildGrantScript(
  provider: string,
  method: CloudGrantMethod,
  externalId?: string,
): string {
  switch (method) {
    case "cli":
      return buildCliGrantScript(provider, externalId);
    case "cloudshell":
      return buildCloudShellGrantScript(provider, externalId);
    case "terraform":
      return buildTerraformDeployScript(provider);
  }
}

export function generateConnectionExternalId(byteLength = 16): string {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
}

export async function copyTextToClipboard(text: string): Promise<boolean> {
  if (!text) return false;
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}
