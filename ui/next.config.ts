import type { NextConfig } from "next";

import { securityHeaders as buildSecurityHeaders } from "./lib/security-headers.mjs";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8422";

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
  // Proxy /v1/* and /health to the FastAPI backend so the dev server works
  // without CORS issues and without needing a separate nginx/caddy setup.
  ...(!isExport && {
    async headers() {
      return [{ source: "/:path*", headers: headersForNextServer }];
    },
    async rewrites() {
      return [
        {
          source: "/v1/:path*",
          destination: `${API_URL}/v1/:path*`,
        },
        {
          source: "/health",
          destination: `${API_URL}/health`,
        },
        {
          source: "/ws/:path*",
          destination: `${API_URL}/ws/:path*`,
        },
      ];
    },
  }),
};

export default nextConfig;
