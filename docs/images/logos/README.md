# Framework and vendor logos

Vendored SVG marks used in the dashboard UI.

## Framework marks (`ui/public/logos/frameworks/`)

Full-color brand tiles (console-style), not monochrome masks. Each mark is a
simplified public-style identity for recognition — not a claim of endorsement.

| File | Framework ids | Visual |
|------|---------------|--------|
| `owasp.svg` | `owasp-llm`, `owasp-mcp`, `owasp-agentic` | Blue hex + wasp |
| `nist.svg` | `nist-ai-rmf`, `nist-csf` | NIST blue + gold rule |
| `mitre-atlas.svg` | `atlas` | MITRE red + ATLAS constellation |
| `cis.svg` | `cis` | CIS blue shield check |
| `iso.svg` | `iso27001` | ISO red seal + 27001 |
| `eu-ai-act.svg` | `eu-ai-act` | EU blue + star circle |
| `soc2.svg` | `soc2` | SOC 2 badge |
| `cmmc.svg` | `cmmc` | CMMC shield badge |

Registered in `ui/lib/framework-logos.ts`. Bump `LOGO_ASSET_REV` when assets change.

## Cloud / vendor marks (`ui/public/logos/`)

Resolved by `ui/lib/vendor-logos.ts` for cloud accounts and integrations.

Official vendor icons used in public diagrams live under
`docs/images/vendor/`. Their first-party download URL, archive member,
retrieval date, exact digest, and use terms are pinned in
`docs/images/vendor/provenance.json`. When redistribution or trademark terms
are unclear, diagrams use a neutral product-category icon instead of a
look-alike mark.

The compact cloud, data-platform, and Kubernetes marks under
`docs/images/vendor/simple-icons/` are unmodified Simple Icons vectors reused
from `msaad00/cloud-ai-security-skills`. They are pinned to the source commit
and digest in the same provenance manifest and retain the upstream CC0-1.0
license. Product names and marks remain trademarks of their owners and are used
only to identify supported evidence sources.

## Adding a mark

1. Add a 32×32 full-color SVG under `ui/public/logos/frameworks/`.
2. Register the path in `ui/lib/framework-logos.ts` and bump `LOGO_ASSET_REV`.
3. Add a row to this table.
