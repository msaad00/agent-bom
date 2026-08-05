// The same question the API, CLI, graph export and mesh answer, asked of the
// browser. These fixture names are copied from
// `tests/test_credential_key_detector_agreement.py`; if the Python predicate
// changes and this port does not, this is where it shows.

import { describe, expect, it } from "vitest";

import { credentialEnvKeys, isCredentialKey } from "@/lib/credential-key";

const CREDENTIALS = [
  "GITHUB_TOKEN",
  "OPENAI_API_KEY",
  "NEO4J_PASSWORD",
  "DATABASE_URL",
  "SSH_KEY",
  "ENCRYPTION_KEY",
  "AUTHORIZATION",
  "CLIENT_SECRET",
  "CA_CERT",
  "AWS_ACCESS_KEY_ID",
  "AZURE_CLIENT_CERTIFICATE_PATH",
  "AZURE_STORAGE_CONNECTION_STRING",
  "SNOWFLAKE_PRIVATE_KEY_PATH",
  "GOOGLE_APPLICATION_CREDENTIALS",
  "PGPASSWORD",
  "ID_RSA",
  "CERTIFICATE",
  "OAUTH",
  "API_KEYS",
  "SSH_KEYS",
  "CREDENTIALS",
];

const NON_CREDENTIALS = [
  "PATH",
  "HOME",
  "LOG_LEVEL",
  "PORT",
  "NODE_ENV",
  "ALLOWED_DIRECTORIES",
  "AUTH_MODE",
  "CERTIFICATE_PATH",
  "DB_CONNECTION_POOL_SIZE",
  "KEYBOARD_LAYOUT",
  "AGENT_BOM_API_KEY_DEFAULT_TTL_SECONDS",
  "AGENT_BOM_AZURE_AUTHORIZATION_MAX_RECORDS",
  "AGENT_BOM_MCP_AUTH_REQUIRE_NETWORK_AUTH",
  "AGENT_BOM_TLS_REQUIRE_CLIENT_CERT",
  "AGENT_BOM_TOKEN_ROTATION_DAYS",
  "CERT_FILE",
  "OAUTH_CLIENT_ID",
  "OAUTH_ENABLED",
  "CREDENTIAL_ROTATION_POLICY",
  "API_KEYS_ENABLED",
];

describe("isCredentialKey", () => {
  it.each(CREDENTIALS)("counts %s as a credential", (name) => {
    expect(isCredentialKey(name)).toBe(true);
  });

  it.each(NON_CREDENTIALS)("leaves %s out of the credential inventory", (name) => {
    expect(isCredentialKey(name)).toBe(false);
  });

  it("returns nothing for an empty or absent env", () => {
    expect(credentialEnvKeys(undefined)).toEqual([]);
    expect(credentialEnvKeys({})).toEqual([]);
  });

  it("counts a mixed env the way the backend does", () => {
    const env = Object.fromEntries([...CREDENTIALS, ...NON_CREDENTIALS].map((name) => [name, "x"]));

    expect(credentialEnvKeys(env).sort()).toEqual([...CREDENTIALS].sort());
  });
});
