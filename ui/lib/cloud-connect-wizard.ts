export type CloudProviderId = "aws" | "azure" | "gcp" | "snowflake";

export type CloudProviderMeta = {
  terraformModule: string;
  inventoryEnv: string;
  scanSurfaces: string[];
  deployNotes: string[];
};

export const CLOUD_PROVIDER_META: Record<CloudProviderId, CloudProviderMeta> = {
  aws: {
    terraformModule: "deploy/terraform/connect-aws",
    inventoryEnv: "AGENT_BOM_AWS_INVENTORY",
    scanSurfaces: ["Inventory", "CIS", "Identities", "AI workloads"],
    deployNotes: [
      "Applies a read-only IAM role with mandatory ExternalId.",
      "After apply, copy role ARN + external_id into the wizard.",
    ],
  },
  azure: {
    terraformModule: "deploy/terraform/connect-azure",
    inventoryEnv: "AGENT_BOM_AZURE_INVENTORY",
    scanSurfaces: ["Inventory", "CIS", "Entra", "Managed AI"],
    deployNotes: [
      "Mints a Reader service principal via Terraform.",
      "Store the client secret once — the control plane encrypts it at rest.",
    ],
  },
  gcp: {
    terraformModule: "deploy/terraform/connect-gcp",
    inventoryEnv: "AGENT_BOM_GCP_INVENTORY",
    scanSurfaces: ["Inventory", "CIS", "IAM", "Vertex AI"],
    deployNotes: [
      "Creates a Viewer service account and JSON key out-of-band.",
      "Paste the key JSON only in the final wizard step.",
    ],
  },
  snowflake: {
    terraformModule: "deploy/terraform/connect-snowflake",
    inventoryEnv: "SNOWFLAKE_ACCOUNT",
    scanSurfaces: ["Governance", "Agents", "Activity", "Warehouses"],
    deployNotes: [
      "Provisions read-only role + key-pair user via Terraform.",
      "Use the generated PEM private key in the wizard secret field.",
    ],
  },
};

export function cloudProviderMeta(provider: string): CloudProviderMeta | null {
  if (provider in CLOUD_PROVIDER_META) {
    return CLOUD_PROVIDER_META[provider as CloudProviderId];
  }
  return null;
}

export function buildTerraformDeployScript(provider: string): string {
  const meta = cloudProviderMeta(provider);
  if (!meta) return "";
  const module = meta.terraformModule;
  return [
    `# ${provider} read-only connector for agent-bom`,
    `terraform -chdir=${module} init`,
    `terraform -chdir=${module} apply`,
    "",
    "# After apply, read outputs for role/account references:",
    `terraform -chdir=${module} output`,
    "",
    `# Enable inventory scans from CLI (optional local smoke):`,
    `export ${meta.inventoryEnv}=1`,
    `agent-bom connect ${provider}`,
  ].join("\n");
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
