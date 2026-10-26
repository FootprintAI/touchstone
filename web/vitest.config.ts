import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

export default defineConfig({
  // The tests render TSX with the automatic runtime, as Next.js does.
  esbuild: { jsx: "automatic" },
  test: {
    environment: "jsdom",
    // jsdom rewrites import.meta.url to http://, so the golden file's path is
    // resolved here, in Node, and handed to the tests.
    env: { GOLDEN_REPORT_PATH: fileURLToPath(new URL("../testdata/report.golden.json", import.meta.url)) },
  },
});
