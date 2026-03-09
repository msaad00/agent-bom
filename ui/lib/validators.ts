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

function isFiniteNum(v: unknown): v is number {
  return typeof v === "number" && isFinite(v);
}

/** Detect prototype-pollution keys anywhere in the JSON text. */
function hasPollutionKeys(jsonText: string): boolean {
  return (
    jsonText.includes('"__proto__"') ||
    jsonText.includes('"constructor"') ||
    // Allow the word "prototype" in values like package names, but
    // explicitly exclude it as a JSON key (preceded by `"prototype"`).
    /"\bprototype\b"\s*:/.test(jsonText)
  );
}

/** Validate a single vulnerability object. Returns an error string or null. */
function validateVuln(v: unknown, path: string): string | null {
  if (!isPlainObject(v)) return `${path}: must be an object`;
  if (!isString(v.id) || !v.id) return `${path}.id: must be a non-empty string`;
  const SEVERITIES = ["critical", "high", "medium", "low", "none"];
  if (!SEVERITIES.includes(v.severity as string))
    return `${path}.severity: must be one of ${SEVERITIES.join(", ")}`;
  if (v.cvss_score !== undefined && !isFiniteNum(v.cvss_score))
    return `${path}.cvss_score: must be a finite number`;
  if (v.epss_score !== undefined && !isFiniteNum(v.epss_score))
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
  if (!isArray(b.affected_agents)) return `${path}.affected_agents: must be an array`;
  if (!isArray(b.exposed_credentials)) return `${path}.exposed_credentials: must be an array`;
  if (!isArray(b.reachable_tools)) return `${path}.reachable_tools: must be an array`;
  if (b.blast_score !== undefined && !isFiniteNum(b.blast_score))
    return `${path}.blast_score: must be a finite number`;
  if (b.cvss_score !== undefined && !isFiniteNum(b.cvss_score))
    return `${path}.cvss_score: must be a finite number`;
  if (b.epss_score !== undefined && !isFiniteNum(b.epss_score))
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
  // 1. Pollution check on raw text (before parsing)
  if (hasPollutionKeys(jsonText)) {
    return { ok: false, error: "Invalid report: unexpected structural keys." };
  }

  // 2. Parse JSON
  let parsed: unknown;
  try {
    parsed = JSON.parse(jsonText);
  } catch (e) {
    return { ok: false, error: `Invalid JSON: ${(e as Error).message}` };
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

  // 6. Validate agents (cap validation at first 200 for perf)
  const agentLimit = Math.min(parsed.agents.length, 200);
  for (let i = 0; i < agentLimit; i++) {
    const err = validateAgent(parsed.agents[i], `agents[${i}]`);
    if (err) return { ok: false, error: err };
  }

  // 7. Validate blast_radius (cap at first 500)
  const blastLimit = Math.min(parsed.blast_radius.length, 500);
  for (let i = 0; i < blastLimit; i++) {
    const err = validateBlast(parsed.blast_radius[i], `blast_radius[${i}]`);
    if (err) return { ok: false, error: err };
  }

  return { ok: true, data: parsed };
}
