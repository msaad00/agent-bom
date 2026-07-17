import { describe, expect, it } from "vitest";

import {
  buildAwsOrgStackSetScript,
  buildCliGrantScript,
  buildCloudShellGrantScript,
  buildGrantScript,
  buildSnowflakeSpcsScript,
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

  it("keeps grant scripts baseline (least privilege) by default", () => {
    // No depth argument → no deep-scan / DSPM grants leak into the script.
    const awsCli = buildCliGrantScript("aws", "abc123");
    expect(awsCli).not.toContain("s3:GetObject");
    expect(buildCliGrantScript("azure")).not.toContain("Key Vault Reader");
    expect(buildCliGrantScript("gcp")).not.toContain("roles/artifactregistry.reader");
    const tf = buildTerraformDeployScript("aws");
    expect(tf).not.toContain("enable_deep_scan_reads");
  });

  it("threads deep-scan into terraform via the existing vars", () => {
    const tf = buildTerraformDeployScript("aws", { deepScan: true });
    expect(tf).toContain("-var enable_deep_scan_reads=true");
    const baseline = buildTerraformDeployScript("aws", { deepScan: false });
    expect(baseline).toContain("-var enable_deep_scan_reads=false");
  });

  it("threads DSPM bucket ARNs into terraform as a scoped var", () => {
    const tf = buildTerraformDeployScript("aws", {
      deepScan: true,
      dspmBuckets: ["arn:aws:s3:::data-lake", "arn:aws:s3:::logs"],
    });
    expect(tf).toContain("enable_deep_scan_reads=true");
    expect(tf).toContain('dspm_s3_bucket_arns=["arn:aws:s3:::data-lake","arn:aws:s3:::logs"]');
  });

  it("adds DSPM S3 object read to the AWS CLI grant, bucket-scoped", () => {
    const cli = buildCliGrantScript("aws", "abc123", {
      deepScan: true,
      dspmBuckets: ["arn:aws:s3:::data-lake"],
    });
    expect(cli).toContain("s3:GetObject");
    expect(cli).toContain("s3:ListBucket");
    expect(cli).toContain("arn:aws:s3:::data-lake");
    expect(cli).toContain("arn:aws:s3:::data-lake/*");
    // Still self-contained + not a wildcard.
    expect(cli).not.toContain('"Resource": "*"\n    }\n  ]\n}\nEOF'); // DSPM stmt is scoped
  });

  it("adds Azure data-plane readers + GCP AR reader on deep-scan", () => {
    const azure = buildCliGrantScript("azure", undefined, { deepScan: true });
    expect(azure).toContain("Key Vault Reader");
    expect(azure).toContain("AcrPull");
    expect(azure).toContain("az role assignment create");
    const gcp = buildCliGrantScript("gcp", undefined, { deepScan: true });
    expect(gcp).toContain("roles/artifactregistry.reader");
  });

  it("routes depth through buildGrantScript for every method", () => {
    expect(buildGrantScript("aws", "terraform", undefined, { deepScan: true })).toContain(
      "enable_deep_scan_reads=true",
    );
    expect(
      buildGrantScript("aws", "cli", "abc123", { deepScan: true, dspmBuckets: ["arn:aws:s3:::b-lake"] }),
    ).toContain("s3:GetObject");
    expect(buildGrantScript("aws", "cloudshell", "abc123", { deepScan: true, dspmBuckets: ["arn:aws:s3:::b-lake"] })).toContain(
      "s3:GetObject",
    );
  });

  it("generates a Snowpark Container Services / Native App deploy recipe", () => {
    // The wizard can generate the SPCS native-app install inline, reusing the
    // shipped package (deploy/snowflake/native-app/) — not the read-only role.
    const script = buildSnowflakeSpcsScript();
    expect(script).toContain("deploy/snowflake/native-app");
    expect(script).toContain("CREATE APPLICATION PACKAGE");
    expect(script).toContain("CREATE APPLICATION agent_bom");
    // Reuses the shipped grant + key-pair scripts (never a password).
    expect(script).toContain("customer_grants_template.sql");
    expect(script).toContain("auth_keypair_setup.sql");
    // Honest: read-only, runs inside the account (no data egress).
    expect(script.toLowerCase()).toContain("read-only");
  });

  it("bakes an account locator into the SPCS recipe when supplied", () => {
    const script = buildSnowflakeSpcsScript({ account: "ORG-ACCT" });
    expect(script).toContain("ORG-ACCT");
  });

  it("generates high-entropy external IDs for AWS trust policies", () => {
    const first = generateConnectionExternalId();
    const second = generateConnectionExternalId();
    expect(first).toHaveLength(32);
    expect(second).toHaveLength(32);
    expect(first).not.toBe(second);
  });
});
