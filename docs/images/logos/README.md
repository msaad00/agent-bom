# Framework and vendor logos

Vendored SVG marks used in the dashboard UI. Prefer monochrome `currentColor` icons so they work in light and dark themes.

## Framework marks (`ui/public/logos/frameworks/`)

| File | Framework ids | Notes |
|------|---------------|-------|
| `owasp.svg` | `owasp-llm`, `owasp-mcp`, `owasp-agentic` | Abstract hex mark; not the OWASP trademark |
| `nist.svg` | `nist-ai-rmf`, `nist-csf` | Monogram-style badge |
| `mitre-atlas.svg` | `atlas` | Monogram-style badge |
| `iso.svg` | `iso27001` | Monogram-style badge |
| `cis.svg` | `cis` | Shield check mark |

Frameworks without a shipped SVG (`eu-ai-act`, `soc2`, `cmmc`) render a colored monogram badge via `ui/lib/framework-logos.ts`.

## Cloud / vendor marks (`ui/public/logos/`)

Resolved by `ui/lib/vendor-logos.ts` for cloud accounts and integrations.

## Adding a mark

1. Add SVG under `ui/public/logos/frameworks/` using `currentColor`.
2. Register the path in `ui/lib/framework-logos.ts`.
3. Add a row to this table.
