import { describe, expect, it } from "vitest";

import {
  buildCliGrantScript,
  buildCloudShellGrantScript,
  buildGrantScript,
  buildTerraformDeployScript,
  cloudGrantMethodLabel,
  cloudProviderMeta,
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

  it("routes buildGrantScript by method", () => {
    expect(buildGrantScript("aws", "terraform")).toContain("terraform -chdir=");
    expect(buildGrantScript("aws", "cli")).toContain("aws iam create-policy");
    expect(buildGrantScript("aws", "cloudshell")).toContain("CloudShell");
    expect(cloudGrantMethodLabel("cli")).toBe("CLI");
  });

  it("generates high-entropy external IDs for AWS trust policies", () => {
    const first = generateConnectionExternalId();
    const second = generateConnectionExternalId();
    expect(first).toHaveLength(32);
    expect(second).toHaveLength(32);
    expect(first).not.toBe(second);
  });
});
