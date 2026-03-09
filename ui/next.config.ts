import type { NextConfig } from "next";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8422";

const nextConfig: NextConfig = {
  images: { unoptimized: true },
  // Proxy /v1/* and /health to the FastAPI backend so the dev server works
  // without CORS issues and without needing a separate nginx/caddy setup.
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
};

export default nextConfig;
