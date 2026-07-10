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

## Adding a mark

1. Add a 32×32 full-color SVG under `ui/public/logos/frameworks/`.
2. Register the path in `ui/lib/framework-logos.ts` and bump `LOGO_ASSET_REV`.
3. Add a row to this table.
