// Whether an environment-variable *name* denotes a credential.
//
// This is a faithful port of `is_credential_key` in `src/agent_bom/constants.py`,
// which is the canonical answer: it decides `MCPServer.credential_names`, the
// graph's credential nodes, blast-radius `exposed_credentials`, and the API's
// mesh and lifecycle graphs. The UI builds a mesh client-side from scan JSON, so
// without this it answered the same question differently and showed a credential
// count no other surface agreed with.
//
// `ui/tests/credential-key.test.ts` holds the same fixture names as
// `tests/test_credential_key_detector_agreement.py`; when the Python predicate
// moves, that test is where the drift shows up.

// Policy/lifecycle settings *about* a credential, not the credential itself.
const CONFIGURATION_WORDS = new Set([
  "age",
  "configured",
  "days",
  "disable",
  "disabled",
  "enable",
  "enabled",
  "expires",
  "expiry",
  "max",
  "method",
  "min",
  "mode",
  "policy",
  "records",
  "require",
  "required",
  "rotated",
  "rotation",
  "seconds",
  "status",
  "ttl",
  "type",
]);

// Authentication material, or a reference to some, wherever the word appears.
const CREDENTIAL_WORDS = new Set([
  "apikey",
  "authorization",
  "bearer",
  "credential",
  "key",
  "password",
  "passwd",
  "secret",
  "token",
]);

// Weaker evidence: credential material alone, a public file or identifier once
// qualified by a locator (`CERTIFICATE` vs `CERTIFICATE_PATH`).
const CREDENTIAL_MATERIAL_WORDS = new Set(["cert", "certificate", "oauth"]);

const LOCATOR_WORDS = new Set([
  "arn",
  "dir",
  "directories",
  "directory",
  "endpoint",
  "file",
  "filename",
  "host",
  "hostname",
  "id",
  "location",
  "name",
  "path",
  "port",
  "ref",
  "url",
]);

const CREDENTIAL_WORD_PAIRS = new Set([
  "ca cert",
  "client cert",
  "client certificate",
  "conn str",
  "connection string",
  "connection uri",
  "connection url",
  "database url",
  "db url",
]);

// Established names for real credentials that contain no credential word at all.
const CREDENTIAL_COMPOUND_NAMES = new Set([
  "id_dsa",
  "id_ecdsa",
  "id_ed25519",
  "id_rsa",
  "mysql_pwd",
  "pgpassword",
]);

const SINGULARIZABLE_WORDS = new Set([...CREDENTIAL_WORDS, ...CREDENTIAL_MATERIAL_WORDS, ...LOCATOR_WORDS]);

// Only known words fold to their singular, so an unrelated plural is left alone:
// `DAYS` must keep matching the configuration word `days`.
function singularize(token: string): string {
  const singular = token.slice(0, -1);
  return token.endsWith("s") && SINGULARIZABLE_WORDS.has(singular) ? singular : token;
}

export function isCredentialKey(name: string): boolean {
  const separated = name.replace(/([a-z0-9])([A-Z])/g, "$1_$2");
  const tokens = (separated.toLowerCase().match(/[a-z0-9]+/g) ?? []).map(singularize);
  if (tokens.length === 0) return false;

  if (tokens.some((token) => CONFIGURATION_WORDS.has(token))) return false;
  if (tokens.includes("no")) return false;

  if (CREDENTIAL_COMPOUND_NAMES.has(tokens.join("_"))) return true;

  if (tokens.some((token) => CREDENTIAL_WORDS.has(token))) return true;

  for (let i = 0; i + 1 < tokens.length; i += 1) {
    if (CREDENTIAL_WORD_PAIRS.has(`${tokens[i]} ${tokens[i + 1]}`)) return true;
  }

  if (
    tokens.some((token) => CREDENTIAL_MATERIAL_WORDS.has(token)) &&
    !tokens.some((token) => LOCATOR_WORDS.has(token))
  ) {
    return true;
  }

  // A terminal AUTH commonly holds an auth header/blob. AUTH_MODE and NO_AUTH
  // are posture settings and must not become credential evidence.
  return tokens[tokens.length - 1] === "auth" && (tokens.length === 1 || tokens[tokens.length - 2] !== "no");
}

export function credentialEnvKeys(env: Record<string, unknown> | null | undefined): string[] {
  return env ? Object.keys(env).filter(isCredentialKey) : [];
}
