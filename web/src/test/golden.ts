import { readFileSync } from "node:fs";
import { fromJson } from "@bufbuild/protobuf";
import { isJsonValue } from "../lib/api";
import { ScanReportSchema, type ScanReport } from "../gen/touchstone/v1/scan_pb";

/** testdata/report.golden.json, written by the Go CLI test; see vitest.config.ts for the path. */
export const goldenPath = process.env.GOLDEN_REPORT_PATH;
if (!goldenPath) {
  throw new Error("GOLDEN_REPORT_PATH is not set; run the tests with vitest (see vitest.config.ts)");
}

/** The JSON text of the golden file. */
export const goldenText = readFileSync(goldenPath, "utf8");

/** The golden report, decoded with the generated parser. */
export function goldenReport(): ScanReport {
  const parsed: unknown = JSON.parse(goldenText);
  if (!isJsonValue(parsed)) {
    throw new Error("golden file is not JSON");
  }
  return fromJson(ScanReportSchema, parsed);
}
