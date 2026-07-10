import { describe, expect, it } from "vitest";

import {
  buildTerraformDeployScript,
  cloudProviderMeta,
  generateConnectionExternalId,
} from "@/lib/cloud-connect-wizard";

describe("cloud-connect-wizard", () => {
  it("maps each live provider to a terraform module and scan surfaces", () => {
    expect(cloudProviderMeta("aws")?.terraformModule).toBe("deploy/terraform/connect-aws");
    expect(cloudProviderMeta("gcp")?.scanSurfaces).toContain("Vertex AI");
    expect(cloudProviderMeta("snowflake")?.scanSurfaces).toContain("Agents");
  });

  it("builds a copy-ready terraform deploy script", () => {
    const script = buildTerraformDeployScript("aws");
    expect(script).toContain("deploy/terraform/connect-aws");
    expect(script).toContain("terraform -chdir=deploy/terraform/connect-aws apply");
    expect(script).toContain("AGENT_BOM_AWS_INVENTORY");
  });

  it("generates high-entropy external IDs for AWS trust policies", () => {
    const first = generateConnectionExternalId();
    const second = generateConnectionExternalId();
    expect(first).toHaveLength(32);
    expect(second).toHaveLength(32);
    expect(first).not.toBe(second);
  });
});
