import type { NextConfig } from "next";
import path from "path";

const nextConfig: NextConfig = {
  // Use standalone mode only when explicitly requested (e.g., Docker)
  ...(process.env.BUILD_STANDALONE === "true" ? { output: "standalone" } : {}),

  // Allow cross-origin images from backend if needed
  images: {
    remotePatterns: [
      { protocol: "http", hostname: "127.0.0.1" },
      { protocol: "http", hostname: "localhost" },
      { protocol: "https", hostname: "**" },
    ],
  },

  // Expose public env vars explicitly (empty default in production to enable relative proxy routing)
  env: {
    NEXT_PUBLIC_API_URL: process.env.NEXT_PUBLIC_API_URL || "",
  },

  // Pin Turbopack's workspace root to THIS directory (frontend/).
  turbopack: {
    root: path.resolve(__dirname),
  },

  // Transparent reverse proxy on Vercel / serverless to eliminate CORS
  async rewrites() {
    let rawUrl =
      process.env.BACKEND_API_URL ||
      process.env.NEXT_PUBLIC_API_URL ||
      "https://phisingweb-production.up.railway.app";

    rawUrl = rawUrl.trim();
    if (!rawUrl.startsWith("http://") && !rawUrl.startsWith("https://") && !rawUrl.startsWith("/")) {
      rawUrl = `https://${rawUrl}`;
    }
    const backendUrl = rawUrl.replace(/\/+$/, "");

    return [
      {
        source: "/api/:path*",
        destination: `${backendUrl}/api/:path*`,
      },
    ];
  },
};

export default nextConfig;
