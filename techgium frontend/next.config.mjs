/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  async rewrites() {
    return [
      {
        // Proxy /api/v1/** → http://localhost:8000/api/v1/**
        // This avoids CORS issues in development when the browser
        // makes requests to the same origin (localhost:3000).
        source: '/api/v1/:path*',
        destination: 'http://localhost:8000/api/v1/:path*',
      },
    ];
  },
};

export default nextConfig;
