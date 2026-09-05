import type { NextConfig } from "next";

import { securityHeaders as buildSecurityHeaders } from "./lib/security-headers.mjs";

// NEXT_EXPORT=1 → static export bundled into the Python package (agent-bom api).
// Rewrites require a running Node server so they are disabled in export mode.
const isExport = process.env.NEXT_EXPORT === "1";

// Single source of truth for CSP + companion headers lives in
// lib/security-headers.ts. ui/scripts/sync-vercel-headers.mjs regenerates
// ui/vercel.json from the same module so the standalone server (this config)
// and the Vercel static deployment never drift. Tests in
// tests/security-headers.test.ts pin the contract.
const securityHeaders = buildSecurityHeaders();
const headersForNextServer =
  process.env.NODE_ENV === "development"
    ? securityHeaders.map((header) =>
        header.key === "Content-Security-Policy"
          ? { ...header, value: header.value.replace("script-src 'self'", "script-src 'self' 'unsafe-eval'") }
          : header,
      )
    : securityHeaders;

const nextConfig: NextConfig = {
  images: { unoptimized: true },
  productionBrowserSourceMaps: false,
  // The Python package uses static export, while the standalone Docker image
  // needs a Node server bundle for the separate control-plane UI container.
  output: isExport ? "export" : "standalone",
  // Server-only runtime routing is owned by server/runtime-api-proxy.ts.
  ...(!isExport && {
    async headers() {
      return [{ source: "/:path*", headers: headersForNextServer }];
    },

  }),
};

export default nextConfig;
