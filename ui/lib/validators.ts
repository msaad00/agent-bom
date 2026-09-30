/**
 * Runtime validation for user-supplied JSON (report import).
 *
 * TypeScript type assertions are compile-time only — they do NOT validate at
 * runtime. Any JSON file a user uploads must be structurally validated before
 * being passed into aggregation functions that assume specific shapes.
 *
 * Threats addressed:
 *  - DoS via oversized file (size check before FileReader)
 *  - App crash from missing/wrong-type fields
 *  - Prototype pollution (__proto__, constructor, prototype keys)
 *  - NaN / Infinity in numeric fields causing math failures
 */

const MAX_IMPORT_BYTES = 10 * 1024 * 1024; // 10 MB

type ValidationResult =
  | { ok: true; data: unknown }
  | { ok: false; error: string };

/** Call BEFORE FileReader.readAsText() to reject oversized files. */
export function checkFileSize(file: File): ValidationResult {
  if (file.size > MAX_IMPORT_BYTES) {
    return {
      ok: false,
      error: `File is ${(file.size / 1024 / 1024).toFixed(1)} MB — maximum is 10 MB.`,
    };
  }
  return { ok: true, data: null };
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function isArray(v: unknown): v is unknown[] {
  return Array.isArray(v);
}

function isString(v: unknown): v is string {
  return typeof v === "string";
}

function isStringArray(v: unknown): v is string[] {
  return Array.isArray(v) && v.every(isString);
}

function isFiniteNum(v: unknown): v is number {
  return typeof v === "number" && isFinite(v);
}

const isCount = (value: unknown): value is number =>
  typeof value === "number" && Number.isSafeInteger(value) && value >= 0;

/** Validate a single vulnerability object. Returns an error string or null. */
function validateVuln(v: unknown, path: string): string | null {
  if (!isPlainObject(v)) return `${path}: must be an object`;
  if (!isString(v.id) || !v.id) return `${path}.id: must be a non-empty string`;
  const SEVERITIES = ["critical", "high", "medium", "low", "none", "unknown"];
  if (!SEVERITIES.includes(v.severity as string))
    return `${path}.severity: must be one of ${SEVERITIES.join(", ")}`;
  if (v.cvss_score != null && !isFiniteNum(v.cvss_score))
    return `${path}.cvss_score: must be a finite number`;
  if (v.epss_score != null && !isFiniteNum(v.epss_score))
    return `${path}.epss_score: must be a finite number`;
  return null;
}

/** Validate a package object. */
function validatePackage(p: unknown, path: string): string | null {
  if (!isPlainObject(p)) return `${path}: must be an object`;
  if (!isString(p.name) || !p.name) return `${path}.name: must be a non-empty string`;
  if (!isString(p.version)) return `${path}.version: must be a string`;
  if (!isString(p.ecosystem)) return `${path}.ecosystem: must be a string`;
  if (p.vulnerabilities !== undefined) {
    if (!isArray(p.vulnerabilities)) return `${path}.vulnerabilities: must be an array`;
    for (let i = 0; i < p.vulnerabilities.length; i++) {
      const err = validateVuln(p.vulnerabilities[i], `${path}.vulnerabilities[${i}]`);
      if (err) return err;
    }
  }
  return null;
}

/** Validate an MCP server object. */
function validateServer(s: unknown, path: string): string | null {
  if (!isPlainObject(s)) return `${path}: must be an object`;
  if (!isString(s.name) || !s.name) return `${path}.name: must be a non-empty string`;
  if (!isArray(s.packages)) return `${path}.packages: must be an array`;
  for (let i = 0; i < s.packages.length; i++) {
    const err = validatePackage(s.packages[i], `${path}.packages[${i}]`);
    if (err) return err;
  }
  return null;
}

/** Validate an agent object. */
function validateAgent(a: unknown, path: string): string | null {
  if (!isPlainObject(a)) return `${path}: must be an object`;
  if (!isString(a.name) || !a.name) return `${path}.name: must be a non-empty string`;
  if (!isString(a.agent_type)) return `${path}.agent_type: must be a string`;
  if (!isArray(a.mcp_servers)) return `${path}.mcp_servers: must be an array`;
  for (let i = 0; i < a.mcp_servers.length; i++) {
    const err = validateServer(a.mcp_servers[i], `${path}.mcp_servers[${i}]`);
    if (err) return err;
  }
  return null;
}

/** Validate a blast_radius entry. */
function validateBlast(b: unknown, path: string): string | null {
  if (!isPlainObject(b)) return `${path}: must be an object`;
  if (!isString(b.vulnerability_id) || !b.vulnerability_id)
    return `${path}.vulnerability_id: must be a non-empty string`;
  if (!isString(b.severity)) return `${path}.severity: must be a string`;
  if (!isStringArray(b.affected_agents)) return `${path}.affected_agents: must be an array of strings`;
  if (!isStringArray(b.exposed_credentials)) return `${path}.exposed_credentials: must be an array of strings`;
  // Current CLI exports expose this relationship as exposed_tools; normalize
  // the older UI name only when absent, without hiding malformed input.
  if (b.reachable_tools === undefined && isArray(b.exposed_tools)) {
    b.reachable_tools = b.exposed_tools;
  }
  if (!isStringArray(b.reachable_tools)) return `${path}.reachable_tools: must be an array of strings`;
  for (const field of ["affected_servers", "exposed_tools"]) {
    if (b[field] != null && !isStringArray(b[field])) return `${path}.${field}: must be an array of strings`;
  }
  for (const field of ["package", "canonical_id", "fixed_version", "impact_category"]) {
    if (b[field] != null && !isString(b[field])) return `${path}.${field}: must be a string`;
  }
  if (b.risk_score != null && !isFiniteNum(b.risk_score)) return `${path}.risk_score: must be a finite number`;
  if (b.blast_score !== undefined && !isFiniteNum(b.blast_score))
    return `${path}.blast_score: must be a finite number`;
  if (b.cvss_score != null && !isFiniteNum(b.cvss_score))
    return `${path}.cvss_score: must be a finite number`;
  if (b.epss_score != null && !isFiniteNum(b.epss_score))
    return `${path}.epss_score: must be a finite number`;
  return null;
}

/**
 * Parse and validate a JSON string from an untrusted file upload.
 *
 * On success returns the parsed data (safe to cast to ScanResult).
 * On failure returns an error string suitable for display to the user.
 */
export function validateScanReport(jsonText: string): ValidationResult {
  // Guard direct callers as well as FileReader, using UTF-8 bytes rather than
  // only JavaScript string length. All accepted records are validated below.
  if (jsonText.length > MAX_IMPORT_BYTES || new TextEncoder().encode(jsonText).byteLength > MAX_IMPORT_BYTES) {
    return { ok: false, error: "Report exceeds the maximum size of 10 MB." };
  }

  let parsed: unknown;
  let unsafeKey = false;
  try {
    parsed = JSON.parse(jsonText, (key, value: unknown) => {
      // The parser decodes escaped keys; reserved words in values stay valid.
      if (key === "__proto__" || key === "constructor" || key === "prototype") {
        unsafeKey = true;
        throw new Error("Unsafe structural key");
      }
      return value;
    });
  } catch {
    return { ok: false, error: unsafeKey ? "Invalid report: unexpected structural keys." : "Invalid JSON report." };
  }

  // 3. Top-level shape
  if (!isPlainObject(parsed)) {
    return { ok: false, error: "Report must be a JSON object." };
  }

  // 4. Required: agents array
  if (!isArray(parsed.agents)) {
    return { ok: false, error: "Missing or invalid \"agents\" field — is this an agent-bom JSON report?" };
  }

  // 5. Required: blast_radius array
  if (!isArray(parsed.blast_radius)) {
    return {
      ok: false,
      error: "Missing or invalid \"blast_radius\" field — is this an agent-bom JSON report?",
    };
  }

  // Canonical totals are rendered directly for an imported report.
  if (parsed.finding_summary !== undefined) {
    const summary = parsed.finding_summary;
    if (!isPlainObject(summary) || !isCount(summary.total) || !isPlainObject(summary.by_severity)) {
      return { ok: false, error: "finding_summary: must contain non-negative safe integer counts" };
    }
    const counts = Object.values(summary.by_severity);
    if (!counts.every(isCount) || counts.reduce((sum, count) => sum + count, 0) !== summary.total) {
      return { ok: false, error: "finding_summary.by_severity: non-negative safe integer counts must sum to total" };
    }
  }

  // Never pass an unchecked tail into dashboard aggregation functions.
  for (let i = 0; i < parsed.agents.length; i++) {
    const err = validateAgent(parsed.agents[i], `agents[${i}]`);
    if (err) return { ok: false, error: err };
  }

  for (let i = 0; i < parsed.blast_radius.length; i++) {
    const err = validateBlast(parsed.blast_radius[i], `blast_radius[${i}]`);
    if (err) return { ok: false, error: err };
  }

  return { ok: true, data: parsed };
}
