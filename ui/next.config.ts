import type { NextConfig } from "next";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8422";

// NEXT_EXPORT=1 → static export bundled into the Python package (agent-bom api).
// Rewrites require a running Node server so they are disabled in export mode.
const isExport = process.env.NEXT_EXPORT === "1";
const securityHeaders = [
  {
    key: "Content-Security-Policy",
    value:
      "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
  },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
];

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
      return [{ source: "/:path*", headers: securityHeaders }];
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
