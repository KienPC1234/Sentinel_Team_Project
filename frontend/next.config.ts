import type { NextConfig } from 'next';

// Giữ nguyên URL Django (trailingSlash) để đối chiếu 1-1.
// /api/* rewrite về Django backend (tránh CORS, giấu target).
const API_TARGET = process.env.API_TARGET || 'http://127.0.0.1:8001';

const nextConfig: NextConfig = {
  trailingSlash: true,
  // Không tự redirect thêm/bớt slash (xem docs skipTrailingSlashRedirect):
  // giữ nguyên path client gửi, rewrite/proxy sang Django không bị loop 301.
  skipTrailingSlashRedirect: true,
  async rewrites() {
    return {
      beforeFiles: [
        {
          source: '/media/:path*',
          destination: `${API_TARGET}/media/:path*`,
        },
        {
          source: '/static/:path*',
          destination: `${API_TARGET}/static/:path*`,
        },
        {
          source: '/ws/:path*',
          destination: `${API_TARGET}/ws/:path*`,
        },
        {
          // Tải script MCP (Django trả file).
          source: '/mcp/download/',
          destination: `${API_TARGET}/mcp/download/`,
        },
        {
          // Thao tác kiểm duyệt báo cáo (approve/reject/analyze/note) — view Django.
          source: '/admin-cp/reports/:id(\\d+)/:action(approve|reject|analyze|note)/',
          destination: `${API_TARGET}/admin-cp/reports/:id/:action/`,
        },
        {
          // Allauth endpoints (Google OAuth, email confirm, ...) proxy sang Django.
          // Negative lookahead để các trang native /accounts/password/reset/*
          // do Next.js phục vụ, không bị proxy đè lên.
          source: '/accounts/:path((?!password/reset/?$)(?!password/reset/confirm)(?!password/reset/key).*)',
          destination: `${API_TARGET}/accounts/:path*`,
        },
      ],
      afterFiles: [],
      fallback: [],
    };
  },
  async headers() {
    return [
      {
        source: '/sw.js',
        headers: [
          { key: 'Content-Type', value: 'application/javascript; charset=utf-8' },
          { key: 'Cache-Control', value: 'no-cache, no-store, must-revalidate' },
          { key: 'Service-Worker-Allowed', value: '/' },
        ],
      },
    ];
  },
};

export default nextConfig;
