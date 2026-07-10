# Brand mark variants (A/B)

Canonical product mark is `../mark-{light,dark}.svg` (**manifest card**).
These files are optional alternatives kept for review — not shipped in the UI.

| File | Concept |
|---|---|
| `b-agent-materials-{light,dark}.svg` | Agent prompt block + materials list |
| `c-brace-bom-{light,dark}.svg` | Code braces framing dependency ticks |

Accent: emerald → cyan (`#34d399` / `#06b6d4` dark; `#059669` / `#0891b2` light).

**Sync rule:** edit `docs/images/brand/mark-*.svg` first, then copy to
`ui/public/brand/` and regenerate `site-docs/assets/brand/mark.svg` /
`mark-mono.svg` / `ui/app/favicon.ico` from the same source.
