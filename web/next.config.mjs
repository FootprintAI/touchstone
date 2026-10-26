/** @type {import("next").NextConfig} */
// The page is exported to web/out and embedded in the Go binary (web/embed.go),
// so there is no Next.js server at runtime.
const nextConfig = {
  output: "export",
};

export default nextConfig;
