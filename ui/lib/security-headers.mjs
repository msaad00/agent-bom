// Single source of truth for the dashboard security response headers.
//
// next.config.ts imports `securityHeaders()` for the dev/standalone server
// path. ui/scripts/sync-vercel-headers.mjs reads from this same module to
// regenerate ui/vercel.json so the static-export Vercel deployment stays in
// lock-step. The vitest sync test in tests/security-headers.test.ts fails if
// either side drifts.
//
// CSP state (issue #1954):
//   - The CSP is now centralized so vercel.json and next.config can no
//     longer drift, and the THEME_BOOTSTRAP_SCRIPT hash is computed and
//     surfaced in INLINE_SCRIPT_HASHES even though the current CSP still
//     keeps `'unsafe-inline'` on script-src.
//   - Removing `'unsafe-inline'` from script-src cleanly requires hashing
//     every inline script Next.js emits during static export (the
//     streaming `__next_f.push(...)` blocks have per-build content), which
//     is a build-time hash-collection job not yet wired. The dashboard CSP
//     served by the Python API (src/agent_bom/api/dashboard_csp.py)
//     already has a hash manifest mechanism and is the prior art for the
//     follow-up. Tracker: #1954 follow-up.
//   - style-src keeps `'unsafe-inline'` because Tailwind v4 + Next.js emit
//     inline style attributes whose contents are not hash-stable per build
//     (computed CSS variables).

import { createHash } from "node:crypto";

import { THEME_BOOTSTRAP_SCRIPT } from "./csp-source.mjs";

function sha256Base64(input) {
  return createHash("sha256").update(input, "utf8").digest("base64");
}

// Inventory of intentional inline scripts the app ships. Their sha256 hashes
// are computed and exported so the follow-up that removes 'unsafe-inline'
// only needs to flip the CSP construction below.
export const INLINE_SCRIPT_HASHES = [`'sha256-${sha256Base64(THEME_BOOTSTRAP_SCRIPT)}'`];

export function cspHeaderValue() {
  return [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline'",
    "script-src-attr 'none'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self' data:",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "frame-ancestors 'none'",
  ].join("; ");
}

export function securityHeaders() {
  return [
    { key: "Content-Security-Policy", value: cspHeaderValue() },
    { key: "X-Content-Type-Options", value: "nosniff" },
    { key: "X-Frame-Options", value: "DENY" },
    { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
    {
      key: "Strict-Transport-Security",
      value: "max-age=31536000; includeSubDomains",
    },
    {
      key: "Permissions-Policy",
      value: "camera=(), microphone=(), geolocation=(), interest-cohort=()",
    },
  ];
}
