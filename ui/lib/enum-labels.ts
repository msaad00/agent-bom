const ACRONYMS = new Set([
  "AI",
  "API",
  "AWS",
  "CI",
  "CIEM",
  "CIS",
  "CSPM",
  "CVE",
  "DSPM",
  "GCP",
  "IAM",
  "KEV",
  "LLM",
  "MCP",
  "PHI",
  "PII",
  "SAST",
  "SBOM",
  "SCA",
]);

/** Turn a backend SCREAMING_SNAKE enum (e.g. `CIS_FAIL`) into a sentence-case label. */
export function humanizeEnum(value: string): string {
  if (!/^[A-Z0-9]+(?:_[A-Z0-9]+)*$/.test(value)) return value;
  return value
    .split("_")
    .map((word, index) => {
      if (ACRONYMS.has(word)) return word;
      const lower = word.toLowerCase();
      return index === 0 ? lower.charAt(0).toUpperCase() + lower.slice(1) : lower;
    })
    .join(" ");
}
