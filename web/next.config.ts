import type { NextConfig } from "next";

// A static export (web/out), embedded into the Go binary by web/embed.go and
// served by `touchstone serve`. The page calls POST /v1/scans on its own origin.
const config: NextConfig = {
  output: "export",
};

export default config;
