import { readFileSync } from "node:fs";
import { fromJson, type JsonValue } from "@bufbuild/protobuf";
import { describe, expect, it } from "vitest";
import {
  Confidence,
  LookupStatus,
  ScanReportSchema,
  ScanStatus,
} from "./gen/touchstone/v1/scan_pb";

// Written by the Go CLI test (go test ./cmd/touchstone -update), so drift
// between the Go and TS sides of scan.proto fails one of the two suites.
const golden = JSON.parse(
  readFileSync(new URL("../../testdata/report.golden.json", import.meta.url), "utf8"),
) as JsonValue;

describe("ScanReport golden", () => {
  it("decodes with the generated parser", () => {
    const report = fromJson(ScanReportSchema, golden);

    expect(report.schemaVersion).toBe("1");
    expect(report.targetUrl).toBe("https://example.com");
    expect(report.scanStatus).toBe(ScanStatus.OK);
    expect(report.lookupStatus).toBe(LookupStatus.COMPLETE);
    expect(report.components).toHaveLength(1);
    expect(report.components[0]?.confidence).toBe(Confidence.LOW);
    expect(report.components[0]?.vulnerabilities[0]?.id).toBe("CVE-2020-11022");
  });
});
