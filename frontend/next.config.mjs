/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true, // intentional — causes double-render in dev to surface side-effect bugs
  // Disable static export of the Pages Router error/404 fallbacks.
  // App Router handles 404 via src/app/not-found.tsx.
  // Without this, Next.js 15 tries to prerender /_error using the Pages Router
  // Html component and fails with "Html should not be imported outside of _document".
  skipTrailingSlashRedirect: true,
  experimental: {
    // Prevent Next.js from prerendering the internal Pages Router error pages
    // when the project uses App Router exclusively.
    missingSuspenseWithCSRBailout: false,
  },
};

export default nextConfig;
