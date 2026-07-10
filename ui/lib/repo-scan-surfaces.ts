export type RepoScanSurface = {
  id: string;
  label: string;
  detail: string;
  languages?: string[] | undefined;
  /** Where this surface runs today (honest parity label). */
  surfaces?: ("api" | "cli" | "mcp" | "ui")[] | undefined;
};

/** Honest catalog of what a public-repo scan auto-detects today (static parse only). */
export const REPO_SCAN_SURFACES: RepoScanSurface[] = [
  {
    id: "agent-frameworks",
    label: "Agent frameworks",
    detail: "LangChain, CrewAI, OpenAI Agents SDK, ADK, LlamaIndex, AutoGen, and related Python stacks",
    languages: ["Python"],
    surfaces: ["api", "cli", "mcp", "ui"],
  },
  {
    id: "mcp-config",
    label: "MCP & agent configs",
    detail: "mcp.json, Claude/Cursor/Windsurf instruction files, MCP server references in markdown",
    languages: ["JSON", "Markdown", "YAML"],
    surfaces: ["api", "cli", "mcp", "ui"],
  },
  {
    id: "skills",
    label: "Skills & instructions",
    detail: "SKILL.md, AGENTS.md, CLAUDE.md — package refs, credential env vars, behavioral audit",
    languages: ["Markdown"],
    surfaces: ["api", "cli", "mcp", "ui"],
  },
  {
    id: "terraform",
    label: "Terraform & cloud AI infra",
    detail: "Bedrock, Vertex, Azure OpenAI, Snowflake Cortex resources; provider versions; hardcoded secrets",
    languages: ["HCL"],
    surfaces: ["api", "cli", "mcp", "ui"],
  },
  {
    id: "iac",
    label: "IaC & deployment configs",
    detail: "Kubernetes, CloudFormation, Helm, Docker, dbt — misconfigurations and AI-adjacent resources",
    languages: ["YAML", "JSON", "HCL"],
    surfaces: ["api", "cli", "mcp", "ui"],
  },
  {
    id: "github-actions",
    label: "CI/CD pipelines",
    detail: "GitHub Actions workflows that invoke agents, models, or supply-chain steps",
    languages: ["YAML"],
    surfaces: ["api", "cli", "mcp", "ui"],
  },
  {
    id: "dependencies",
    label: "Dependencies & supply chain",
    detail: "uv.lock, requirements.txt, poetry.lock, package-lock.json, go.sum, Cargo.lock — pinned versions with OSV/CVE enrichment when enabled",
    languages: ["Python", "Node", "Go", "Ruby", "Rust", "…"],
    surfaces: ["api", "cli", "mcp", "ui"],
  },
  {
    id: "jupyter",
    label: "Jupyter notebooks",
    detail: "Auto-walks .ipynb files for AI/ML imports, pip installs, model references, and credential env vars",
    languages: ["Python"],
    surfaces: ["api", "cli", "mcp", "ui"],
  },
  {
    id: "secrets",
    label: "Secrets & credentials",
    detail: "Hardcoded API keys, tokens, private keys, and connection strings in source and config files",
    languages: ["Python", "TS/JS", "YAML", "JSON", "env"],
    surfaces: ["api", "cli", "mcp", "ui"],
  },
  {
    id: "weak-crypto",
    label: "Weak cryptography",
    detail: "MD5/SHA-1 hashes, DES/RC4 ciphers, ECB mode, and deprecated TLS protocol usage in application code",
    languages: ["Python", "TS/JS", "Go", "Java", "…"],
    surfaces: ["api", "cli", "mcp", "ui"],
  },
  {
    id: "sast",
    label: "SAST / code paths",
    detail: "Semgrep rules across the repo tree when semgrep is installed on the control plane (optional — skipped gracefully if absent)",
    languages: ["Python", "TS/JS", "Go", "Java", "…"],
    surfaces: ["api", "cli", "mcp"],
  },
  {
    id: "connectors",
    label: "SaaS connectors (Jira, Slack, …)",
    detail: "Not part of git repo scans — onboard via Cloud Accounts or Data Sources with connector credentials",
    languages: ["API"],
    surfaces: ["api", "cli", "ui"],
  },
  {
    id: "ingestion",
    label: "Data & ingestion code",
    detail: "ETL/pipeline Python, SQL, and infra wiring when present in the repo tree",
    languages: ["Python", "SQL"],
    surfaces: ["api", "cli", "mcp", "ui"],
  },
];

export function repoScanLanguageSummary(): string {
  const languages = new Set<string>();
  for (const surface of REPO_SCAN_SURFACES) {
    for (const language of surface.languages ?? []) {
      if (language !== "…" && language !== "API") languages.add(language);
    }
  }
  return `${languages.size}+ languages and config formats`;
}

export function repoScanApiSurfaces(): RepoScanSurface[] {
  return REPO_SCAN_SURFACES.filter((surface) => surface.surfaces?.includes("api") ?? true);
}
