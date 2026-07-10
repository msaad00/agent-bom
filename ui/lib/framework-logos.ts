/**
 * Compliance framework marks under `public/logos/frameworks/`.
 * `frameworkLogoMeta(id)` returns a vendored SVG path or a monogram fallback
 * when no mark is shipped (EU AI Act, SOC 2, CMMC).
 */

export type FrameworkLogoId =
  | "owasp-llm"
  | "owasp-mcp"
  | "owasp-agentic"
  | "atlas"
  | "nist-ai-rmf"
  | "nist-csf"
  | "eu-ai-act"
  | "iso27001"
  | "soc2"
  | "cis"
  | "cmmc";

export type FrameworkLogoMeta = {
  id: FrameworkLogoId;
  /** Monogram shown when `src` is null or the image fails to load. */
  monogram: string;
  /** Vendored SVG path, or null for monogram-only frameworks. */
  src: string | null;
  /** Tailwind classes for the monogram badge. */
  badgeClass: string;
};

/** Bump when framework SVGs change so browsers drop stale caches. */
const LOGO_ASSET_REV = "v5";

const LOGO_PATH: Partial<Record<FrameworkLogoId, string>> = {
  "owasp-llm": `/logos/frameworks/owasp.svg?${LOGO_ASSET_REV}`,
  "owasp-mcp": `/logos/frameworks/owasp.svg?${LOGO_ASSET_REV}`,
  "owasp-agentic": `/logos/frameworks/owasp.svg?${LOGO_ASSET_REV}`,
  atlas: `/logos/frameworks/mitre-atlas.svg?${LOGO_ASSET_REV}`,
  "nist-ai-rmf": `/logos/frameworks/nist-ai-rmf.svg?${LOGO_ASSET_REV}`,
  "nist-csf": `/logos/frameworks/nist-csf.svg?${LOGO_ASSET_REV}`,
  iso27001: `/logos/frameworks/iso.svg?${LOGO_ASSET_REV}`,
  cis: `/logos/frameworks/cis.svg?${LOGO_ASSET_REV}`,
  "eu-ai-act": `/logos/frameworks/eu-ai-act.svg?${LOGO_ASSET_REV}`,
  soc2: `/logos/frameworks/soc2.svg?${LOGO_ASSET_REV}`,
  cmmc: `/logos/frameworks/cmmc.svg?${LOGO_ASSET_REV}`,
};

/** Theme-token badges — readable on both light and dark (no dark-only pastels). */
const META: Record<FrameworkLogoId, Omit<FrameworkLogoMeta, "src">> = {
  "owasp-llm": {
    id: "owasp-llm",
    monogram: "OW",
    badgeClass: "border-amber-600/45 bg-amber-500/15 text-[color:var(--foreground)]",
  },
  "owasp-mcp": {
    id: "owasp-mcp",
    monogram: "MC",
    badgeClass: "border-amber-600/45 bg-amber-500/15 text-[color:var(--foreground)]",
  },
  "owasp-agentic": {
    id: "owasp-agentic",
    monogram: "AG",
    badgeClass: "border-fuchsia-600/45 bg-fuchsia-500/15 text-[color:var(--foreground)]",
  },
  atlas: {
    id: "atlas",
    monogram: "AT",
    badgeClass: "border-fuchsia-600/45 bg-fuchsia-500/15 text-[color:var(--foreground)]",
  },
  "nist-ai-rmf": {
    id: "nist-ai-rmf",
    monogram: "AI",
    badgeClass: "border-sky-600/45 bg-sky-500/15 text-[color:var(--foreground)]",
  },
  "nist-csf": {
    id: "nist-csf",
    monogram: "CS",
    badgeClass: "border-teal-600/45 bg-teal-500/15 text-[color:var(--foreground)]",
  },
  "eu-ai-act": {
    id: "eu-ai-act",
    monogram: "EU",
    badgeClass: "border-blue-600/45 bg-blue-500/15 text-[color:var(--foreground)]",
  },
  iso27001: {
    id: "iso27001",
    monogram: "ISO",
    badgeClass: "border-sky-600/45 bg-sky-500/15 text-[color:var(--foreground)]",
  },
  soc2: {
    id: "soc2",
    monogram: "S2",
    badgeClass: "border-indigo-600/45 bg-indigo-500/15 text-[color:var(--foreground)]",
  },
  cis: {
    id: "cis",
    monogram: "CIS",
    badgeClass: "border-lime-600/45 bg-lime-500/15 text-[color:var(--foreground)]",
  },
  cmmc: {
    id: "cmmc",
    monogram: "CM",
    badgeClass: "border-rose-600/45 bg-rose-500/15 text-[color:var(--foreground)]",
  },
};

const ALIASES: Record<string, FrameworkLogoId> = {
  owasp: "owasp-llm",
  "owasp llm": "owasp-llm",
  "owasp llm top 10": "owasp-llm",
  "owasp mcp": "owasp-mcp",
  "owasp mcp top 10": "owasp-mcp",
  "owasp agentic": "owasp-agentic",
  "owasp agentic top 10": "owasp-agentic",
  "mitre atlas": "atlas",
  atlas: "atlas",
  "nist ai rmf": "nist-ai-rmf",
  "nist csf": "nist-csf",
  "nist csf 2.0": "nist-csf",
  "eu ai act": "eu-ai-act",
  iso27001: "iso27001",
  "iso 27001": "iso27001",
  soc2: "soc2",
  "soc 2": "soc2",
  cis: "cis",
  "cis controls": "cis",
  cmmc: "cmmc",
  "cmmc 2.0": "cmmc",
};

export function normalizeFrameworkLogoId(id: string | null | undefined): FrameworkLogoId | null {
  if (!id) return null;
  const key = id.trim().toLowerCase();
  if (key in META) return key as FrameworkLogoId;
  return ALIASES[key] ?? null;
}

/** Resolve a framework id/label to logo metadata for UI rendering. */
export function frameworkLogoMeta(id: string | null | undefined): FrameworkLogoMeta | null {
  const normalized = normalizeFrameworkLogoId(id);
  if (!normalized) return null;
  const base = META[normalized];
  return { ...base, src: LOGO_PATH[normalized] ?? null };
}
