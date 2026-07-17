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

/**
 * Least-privilege read-only permission policy, inlined so the generated grant
 * script is self-contained. CloudShell (and most operator shells) have no repo
 * checkout, so a `file://scripts/provision/...` reference fails with
 * "No such file". Mirrors scripts/provision/aws_readonly_policy.json.
 */
export const AWS_READONLY_POLICY = {
  Version: "2012-10-17",
  Statement: [
    {
      Sid: "BedrockAgentDiscovery",
      Effect: "Allow",
      Action: [
        "bedrock:ListAgents",
        "bedrock:GetAgent",
        "bedrock:ListAgentVersions",
        "bedrock:GetAgentVersion",
        "bedrock:ListAgentActionGroups",
        "bedrock:GetAgentActionGroup",
        "bedrock:ListFoundationModels",
        "bedrock:GetFoundationModel",
      ],
      Resource: "*",
    },
    {
      Sid: "LambdaDiscovery",
      Effect: "Allow",
      Action: [
        "lambda:ListFunctions",
        "lambda:GetFunction",
        "lambda:GetFunctionConfiguration",
        "lambda:ListLayers",
        "lambda:GetLayerVersion",
        "lambda:GetLayerVersionByArn",
        "lambda:ListTags",
      ],
      Resource: "*",
    },
    {
      Sid: "ECSDiscovery",
      Effect: "Allow",
      Action: [
        "ecs:ListClusters",
        "ecs:ListTasks",
        "ecs:DescribeTasks",
        "ecs:DescribeTaskDefinition",
        "ecs:ListContainerInstances",
        "ecs:DescribeContainerInstances",
      ],
      Resource: "*",
    },
    {
      Sid: "EKSDiscovery",
      Effect: "Allow",
      Action: [
        "eks:ListClusters",
        "eks:DescribeCluster",
        "eks:ListNodegroups",
        "eks:DescribeNodegroup",
        "eks:ListAddons",
        "eks:DescribeAddon",
      ],
      Resource: "*",
    },
    {
      Sid: "SageMakerDiscovery",
      Effect: "Allow",
      Action: [
        "sagemaker:ListEndpoints",
        "sagemaker:DescribeEndpoint",
        "sagemaker:ListModels",
        "sagemaker:DescribeModel",
        "sagemaker:ListNotebookInstances",
        "sagemaker:DescribeNotebookInstance",
        "sagemaker:ListTrainingJobs",
        "sagemaker:DescribeTrainingJob",
      ],
      Resource: "*",
    },
    {
      Sid: "EC2GPUDiscovery",
      Effect: "Allow",
      Action: [
        "ec2:DescribeInstances",
        "ec2:DescribeInstanceTypes",
        "ec2:DescribeImages",
        "ec2:DescribeRegions",
        "ec2:DescribeTags",
      ],
      Resource: "*",
    },
    {
      Sid: "ECRImagePull",
      Effect: "Allow",
      Action: [
        "ecr:GetAuthorizationToken",
        "ecr:DescribeRepositories",
        "ecr:ListImages",
        "ecr:DescribeImages",
        "ecr:GetDownloadUrlForLayer",
        "ecr:BatchGetImage",
      ],
      Resource: "*",
    },
    {
      Sid: "CloudTrailAudit",
      Effect: "Allow",
      Action: [
        "cloudtrail:LookupEvents",
        "cloudtrail:GetTrailStatus",
        "cloudtrail:DescribeTrails",
      ],
      Resource: "*",
    },
    {
      Sid: "IAMReadOnly",
      Effect: "Allow",
      Action: [
        "iam:ListRoles",
        "iam:GetRole",
        "iam:ListAttachedRolePolicies",
        "iam:ListRolePolicies",
        "iam:GetRolePolicy",
      ],
      Resource: "*",
    },
  ],
} as const;

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
        `# Idempotent + self-contained: safe to re-run, no repo checkout needed.`,
        `ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)`,
        `EXTERNAL_ID=${eid}`,
        `POLICY_ARN="arn:aws:iam::\${ACCOUNT_ID}:policy/agent-bom-readonly"`,
        "",
        `# Read-only permission policy (inlined — CloudShell has no repo checkout).`,
        `cat > /tmp/agent-bom-readonly.json <<'EOF'`,
        JSON.stringify(AWS_READONLY_POLICY, null, 2),
        `EOF`,
        "",
        `# Trust policy: this account's root may assume the role only with the ExternalId.`,
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
        `# Create-or-update the permission policy (idempotent on re-run).`,
        `if aws iam get-policy --policy-arn "\${POLICY_ARN}" >/dev/null 2>&1; then`,
        `  aws iam create-policy-version --policy-arn "\${POLICY_ARN}" \\`,
        `    --policy-document file:///tmp/agent-bom-readonly.json --set-as-default`,
        `else`,
        `  aws iam create-policy --policy-name agent-bom-readonly \\`,
        `    --policy-document file:///tmp/agent-bom-readonly.json`,
        `fi`,
        "",
        `# Create-or-update the role + its trust (idempotent on re-run).`,
        `if aws iam get-role --role-name agent-bom-readonly >/dev/null 2>&1; then`,
        `  aws iam update-assume-role-policy --role-name agent-bom-readonly \\`,
        `    --policy-document file:///tmp/agent-bom-trust.json`,
        `else`,
        `  aws iam create-role --role-name agent-bom-readonly \\`,
        `    --assume-role-policy-document file:///tmp/agent-bom-trust.json`,
        `fi`,
        "",
        `# Attach the read-only policies (attach is idempotent).`,
        `aws iam attach-role-policy --role-name agent-bom-readonly --policy-arn "\${POLICY_ARN}"`,
        `# AWS managed SecurityAudit adds broad read coverage:`,
        `aws iam attach-role-policy --role-name agent-bom-readonly \\`,
        `  --policy-arn arn:aws:iam::aws:policy/SecurityAudit`,
        "",
        `echo "Role ARN: arn:aws:iam::\${ACCOUNT_ID}:role/agent-bom-readonly"`,
        `echo "ExternalId: \${EXTERNAL_ID}"`,
        ...grantFooter(provider, meta.inventoryEnv),
      ].join("\n");

    case "azure":
      return [
        `# Azure read-only grant for agent-bom (Azure CLI)`,
        `# Note: re-running create-for-rbac mints a NEW secret each time. If you`,
        `# already have the SP, reuse its secret or reset it with:`,
        `#   az ad sp credential reset --id <appId>`,
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
        `# Create the service account if it does not already exist (idempotent).`,
        `gcloud iam service-accounts describe "\${SA_EMAIL}" >/dev/null 2>&1 || \\`,
        `  gcloud iam service-accounts create \${SA_NAME} \\`,
        `    --display-name="agent-bom read-only scanner"`,
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

/**
 * Consistent read-only role name minted in every member account by the org
 * StackSet — the same name the org fan-out assumes per account
 * (`AGENT_BOM_AWS_ORG_ROLE_NAME`, default `agent-bom-readonly` in
 * `src/agent_bom/cloud/aws_organizations.py`). Keep the two in lockstep.
 */
export const DEFAULT_AWS_ORG_ROLE_NAME = "agent-bom-readonly";

/**
 * Whole-AWS-Organization onboarding via a CloudFormation StackSet — the
 * org-scale path (deploy ONCE from the management / delegated-admin account,
 * every member account gets an identical read-only role, and new accounts
 * auto-enroll) instead of onboarding accounts one at a time.
 *
 * Mirrors the commands in `deploy/cloudformation/README.md` and deploys the
 * shipped `deploy/cloudformation/agent-bom-readonly-role.yaml` template. The
 * ExternalId round-trips into the StackSet parameters so the SAME value the
 * wizard stores guards every per-account AssumeRole. Read-only only
 * (SecurityAudit / ViewOnlyAccess), short-lived STS, no static keys.
 */
export function buildAwsOrgStackSetScript(
  externalId?: string,
  roleName: string = DEFAULT_AWS_ORG_ROLE_NAME,
): string {
  const eid = (externalId ?? "").trim() || "<EXTERNAL_ID>";
  const name = roleName.trim() || DEFAULT_AWS_ORG_ROLE_NAME;
  return [
    `# agent-bom read-only role across your WHOLE AWS Organization (CloudFormation StackSet).`,
    `# Run from the org MANAGEMENT account (or a delegated StackSets admin) with`,
    `# service-managed StackSets trusted access enabled. Deploy ONCE — every member`,
    `# account gets an identical read-only "${name}" role and new accounts auto-enroll.`,
    `# Never onboard accounts one by one.`,
    `EXTERNAL_ID=${eid}`,
    `ROLE_NAME=${name}`,
    `CONTROL_PLANE_PRINCIPAL_ARN=<CONTROL_PLANE_PRINCIPAL_ARN>  # the identity agent-bom assumes from`,
    `ROOT_OU_ID=<ROOT_OR_TARGET_OU_ID>                          # org root r-xxxx or an ou-xxxx-... id`,
    ``,
    `# 1. Create the StackSet (service-managed, auto-deploy to new accounts).`,
    `aws cloudformation create-stack-set \\`,
    `  --stack-set-name "$ROLE_NAME" \\`,
    `  --template-body file://deploy/cloudformation/agent-bom-readonly-role.yaml \\`,
    `  --permission-model SERVICE_MANAGED \\`,
    `  --auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false \\`,
    `  --capabilities CAPABILITY_NAMED_IAM \\`,
    `  --parameters ParameterKey=ExternalId,ParameterValue="$EXTERNAL_ID" \\`,
    `               ParameterKey=TrustedPrincipalArn,ParameterValue="$CONTROL_PLANE_PRINCIPAL_ARN" \\`,
    `               ParameterKey=RoleName,ParameterValue="$ROLE_NAME"`,
    ``,
    `# 2. Roll it out to every account under the org root / target OU.`,
    `aws cloudformation create-stack-instances \\`,
    `  --stack-set-name "$ROLE_NAME" \\`,
    `  --deployment-targets OrganizationalUnitIds="\${ROOT_OU_ID}" \\`,
    `  --regions us-east-1 \\`,
    `  --operation-preferences MaxConcurrentPercentage=100,FailureTolerancePercentage=20`,
    ``,
    `# 3. Register THIS management account's ${name} role ARN in the next step.`,
    `#    agent-bom enumerates the org and assumes the same read-only role in each`,
    `#    member account (short-lived STS + this ExternalId) — read-only, no keys.`,
  ].join("\n");
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
