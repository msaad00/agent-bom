// Single source of truth for the dashboard security response headers.
//
// next.config.ts imports `securityHeaders()` for the dev/standalone server
// path. ui/scripts/sync-vercel-headers.mjs reads from this same module to
// regenerate ui/vercel.json so the static-export Vercel deployment stays in
// lock-step. The vitest sync test in tests/security-headers.test.ts fails if
// either side drifts.
//
// CSP design (issue #1954):
//   - script-src is hash-pinned: 'self' plus the sha256 of every inline
//     script the app intentionally ships. THEME_BOOTSTRAP_SCRIPT is the
//     only inline script today; if a new one is added, register it here.
//   - script-src does NOT carry 'unsafe-inline'. Removing it closes the
//     XSS sink that previously allowed any injected inline <script> to run.
//   - style-src still carries 'unsafe-inline' because Tailwind v4 + Next.js
//     emit inline style attributes whose contents are not hash-stable per
//     build (computed CSS variables). Tracker for migration: a follow-up
//     to #1954; until then the CSP is markedly stricter than before but
//     not yet pure-hash on style.

import { createHash } from "node:crypto";

import { THEME_BOOTSTRAP_SCRIPT } from "./csp-source.mjs";

function sha256Base64(input) {
  return createHash("sha256").update(input, "utf8").digest("base64");
}

const INLINE_SCRIPT_HASHES = [`'sha256-${sha256Base64(THEME_BOOTSTRAP_SCRIPT)}'`];

export function cspHeaderValue() {
  const scriptSrc = ["'self'", ...INLINE_SCRIPT_HASHES].join(" ");
  return [
    "default-src 'self'",
    `script-src ${scriptSrc}`,
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
