import type { NextConfig } from "next";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8422";

// NEXT_EXPORT=1 → static export bundled into the Python package (agent-bom api).
// Rewrites require a running Node server so they are disabled in export mode.
const isExport = process.env.NEXT_EXPORT === "1";

const nextConfig: NextConfig = {
  images: { unoptimized: true },
  ...(isExport && { output: "export" }),
  // Proxy /v1/* and /health to the FastAPI backend so the dev server works
  // without CORS issues and without needing a separate nginx/caddy setup.
  ...(!isExport && {
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
