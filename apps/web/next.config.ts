import type { NextConfig } from "next";

// 127.0.0.1 rather than localhost: Node may resolve localhost to ::1 while uvicorn listens on IPv4.
const apiUrl = process.env.API_INTERNAL_URL ?? "http://127.0.0.1:8000";

const nextConfig: NextConfig = {
  output: "standalone",
  poweredByHeader: false,
  // In docker-compose the reverse proxy routes /api; this rewrite covers `npm run dev`
  // and keeps the browser on a single origin so the session cookie stays httpOnly + SameSite.
  async rewrites() {
    return [{ source: "/api/:path*", destination: `${apiUrl}/api/:path*` }];
  },
};

export default nextConfig;
