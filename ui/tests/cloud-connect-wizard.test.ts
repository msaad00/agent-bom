import { describe, expect, it } from "vitest";

import {
  buildAwsOrgStackSetScript,
  buildCliGrantScript,
  buildCloudShellGrantScript,
  buildGrantScript,
  buildTerraformDeployScript,
  cloudGrantMethodLabel,
  cloudProviderMeta,
  DEFAULT_AWS_ORG_ROLE_NAME,
  generateConnectionExternalId,
} from "@/lib/cloud-connect-wizard";

describe("cloud-connect-wizard", () => {
  it("maps each live provider to terraform, provision script, and scan surfaces", () => {
    expect(cloudProviderMeta("aws")?.terraformModule).toBe("deploy/terraform/connect-aws");
    expect(cloudProviderMeta("aws")?.provisionScript).toContain("aws_readonly_policy.json");
    expect(cloudProviderMeta("gcp")?.scanSurfaces).toContain("Vertex AI");
    expect(cloudProviderMeta("snowflake")?.scanSurfaces).toContain("Agents");
    expect(cloudProviderMeta("azure")?.cloudShellLabel).toMatch(/Cloud Shell/i);
  });

  it("builds a copy-ready terraform deploy script", () => {
    const script = buildTerraformDeployScript("aws");
    expect(script).toContain("deploy/terraform/connect-aws");
    expect(script).toContain("terraform -chdir=deploy/terraform/connect-aws apply");
    expect(script).toContain("AGENT_BOM_AWS_INVENTORY");
  });

  it("builds CLI and CloudShell grant scripts for each provider", () => {
    const awsCli = buildCliGrantScript("aws", "abc123");
    expect(awsCli).toContain("aws iam create-role");
    expect(awsCli).toContain("EXTERNAL_ID=abc123");
    expect(awsCli).toContain("SecurityAudit");

    const awsShell = buildCloudShellGrantScript("aws", "abc123");
    expect(awsShell).toContain("AWS CloudShell");
    expect(awsShell).toContain("aws iam create-role");

    expect(buildCliGrantScript("azure")).toContain("az ad sp create-for-rbac");
    expect(buildCloudShellGrantScript("azure")).toContain("Azure Cloud Shell");
    expect(buildCliGrantScript("gcp")).toContain("gcloud iam service-accounts create");
    expect(buildCloudShellGrantScript("gcp")).toContain("Google Cloud Shell");
    expect(buildCliGrantScript("snowflake")).toContain("snow sql -f");
    expect(buildCloudShellGrantScript("snowflake")).toContain("Snowsight");
  });

  it("inlines the AWS read-only policy instead of a repo file:// path", () => {
    // Bug: `--policy-document file://scripts/provision/aws_readonly_policy.json`
    // fails with "No such file" in CloudShell (no repo checkout). The policy
    // must be embedded via heredoc so the script is self-contained.
    const awsCli = buildCliGrantScript("aws", "abc123");
    expect(awsCli).not.toContain("file://scripts/");
    expect(awsCli).not.toContain("file://" + "scripts/provision");
    expect(awsCli).toContain("cat > /tmp/agent-bom-readonly.json <<'EOF'");
    expect(awsCli).toContain("bedrock:ListAgents");
    expect(awsCli).toContain("--policy-document file:///tmp/agent-bom-readonly.json");
    // CloudShell variant must carry the same self-contained policy.
    expect(buildCloudShellGrantScript("aws", "abc123")).toContain(
      "cat > /tmp/agent-bom-readonly.json <<'EOF'",
    );
  });

  it("makes the AWS grant idempotent (create-or-update on re-run)", () => {
    // Bug: create-role / create-policy fail EntityAlreadyExists on re-run,
    // leaving the trust/ExternalId un-applied. Guard with get + update paths.
    const awsCli = buildCliGrantScript("aws", "abc123");
    expect(awsCli).toContain("aws iam get-role --role-name agent-bom-readonly");
    expect(awsCli).toContain("aws iam update-assume-role-policy");
    expect(awsCli).toContain('aws iam get-policy --policy-arn "${POLICY_ARN}"');
    expect(awsCli).toContain("aws iam create-policy-version");
    expect(awsCli).toContain("--set-as-default");
  });

  it("makes the GCP service-account create idempotent", () => {
    const gcpCli = buildCliGrantScript("gcp");
    expect(gcpCli).toContain("gcloud iam service-accounts describe");
    // The create is guarded so a re-run does not fail ALREADY_EXISTS.
    expect(gcpCli).toContain('describe "${SA_EMAIL}" >/dev/null 2>&1 ||');
  });

  it("routes buildGrantScript by method", () => {
    expect(buildGrantScript("aws", "terraform")).toContain("terraform -chdir=");
    expect(buildGrantScript("aws", "cli")).toContain("aws iam create-policy");
    expect(buildGrantScript("aws", "cloudshell")).toContain("CloudShell");
    expect(cloudGrantMethodLabel("cli")).toBe("CLI");
  });

  it("builds an org-wide CloudFormation StackSet grant (deploy once, auto-enroll)", () => {
    // The org-scale path: one StackSet from the management account mints an
    // identical read-only role in every member account and auto-enrolls new ones,
    // instead of onboarding accounts one by one.
    const script = buildAwsOrgStackSetScript("abc123");
    expect(DEFAULT_AWS_ORG_ROLE_NAME).toBe("agent-bom-readonly");
    // StackSet create + rollout commands, matching deploy/cloudformation/README.md.
    expect(script).toContain("aws cloudformation create-stack-set");
    expect(script).toContain("aws cloudformation create-stack-instances");
    expect(script).toContain("--permission-model SERVICE_MANAGED");
    expect(script).toContain("--auto-deployment Enabled=true");
    expect(script).toContain('OrganizationalUnitIds="${ROOT_OU_ID}"');
    expect(script).toContain("CAPABILITY_NAMED_IAM");
    // The consistent role name the org fan-out assumes in each account.
    expect(script).toContain("agent-bom-readonly");
    // The ExternalId round-trips into the StackSet parameters.
    expect(script).toContain("EXTERNAL_ID=abc123");
    expect(script).toContain("ParameterKey=ExternalId");
    // Points at the shipped template.
    expect(script).toContain("deploy/cloudformation/agent-bom-readonly-role.yaml");
    // Honest: register the management account's role ARN afterwards.
    expect(script.toLowerCase()).toContain("management");
  });

  it("defaults the StackSet role name and falls back to a placeholder ExternalId", () => {
    const script = buildAwsOrgStackSetScript();
    expect(script).toContain("ROLE_NAME=agent-bom-readonly");
    expect(script).toContain("EXTERNAL_ID=<EXTERNAL_ID>");
  });

  it("generates high-entropy external IDs for AWS trust policies", () => {
    const first = generateConnectionExternalId();
    const second = generateConnectionExternalId();
    expect(first).toHaveLength(32);
    expect(second).toHaveLength(32);
    expect(first).not.toBe(second);
  });
});
