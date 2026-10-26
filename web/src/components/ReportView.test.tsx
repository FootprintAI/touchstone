import { readFileSync } from "node:fs";
import { fromJson, type JsonObject, type JsonValue } from "@bufbuild/protobuf";
import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ScanReportSchema } from "../gen/touchstone/v1/scan_pb";
import { ReportView } from "./ReportView";

const golden = JSON.parse(
  readFileSync(new URL("../../../testdata/report.golden.json", import.meta.url), "utf8"),
) as JsonObject;

function renderReport(overrides: Record<string, JsonValue> = {}) {
  const report = fromJson(ScanReportSchema, { ...golden, ...overrides });
  return render(<ReportView report={report} />);
}

const component = (name: string, confidence: string): JsonObject => ({
  name,
  version: "1.0.0",
  purl: `pkg:npm/${name}@1.0.0`,
  confidence,
  evidence: [{ kind: "EVIDENCE_KIND_FINGERPRINT_ASSET", location: `https://example.com/${name}.js`, detail: name }],
});

describe("ReportView", () => {
  it("shows the jQuery component under Low confidence with its CVE and evidence", () => {
    renderReport();

    const low = screen.getByRole("region", { name: "Low confidence" });
    expect(within(low).getByRole("heading", { name: "jquery 1.12.4" })).toBeInTheDocument();
    expect(within(low).getByText("CVE-2020-11022")).toBeInTheDocument();
    expect(within(low).getByText(/Potential XSS vulnerability/)).toBeInTheDocument();
    expect(within(low).getByText("CVSS 6.1")).toBeInTheDocument();
    expect(within(low).getByText("Evidence (1)")).toBeInTheDocument();
    expect(within(low).getByText("jquery-1.12.4.min.js")).toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "High confidence" })).not.toBeInTheDocument();
  });

  it("groups components by tier, best evidence first", () => {
    renderReport({
      components: [
        component("low-lib", "CONFIDENCE_LOW"),
        component("high-lib", "CONFIDENCE_HIGH"),
        component("mid-lib", "CONFIDENCE_MEDIUM"),
      ],
    });

    const tiers = screen
      .getAllByRole("region")
      .map((r) => r.getAttribute("aria-label"))
      .filter((label) => label?.endsWith("confidence"));
    expect(tiers).toEqual(["High confidence", "Medium confidence", "Low confidence"]);
    expect(
      within(screen.getByRole("region", { name: "High confidence" })).getByText("high-lib 1.0.0"),
    ).toBeInTheDocument();
  });

  it("lists every checked location with its reason and result", () => {
    renderReport({
      checked: [
        { url: "https://example.com", reason: "TARGET", result: "RESULT_FOUND" },
        { url: "https://example.com/.well-known/security.txt", reason: "DISCOVERY_PATH", result: "RESULT_NOT_FOUND" },
        { url: "https://example.com/x.js", reason: "SUBRESOURCE", result: "RESULT_ERROR", error: "timeout" },
      ],
    });

    const section = screen.getByRole("heading", { name: "Checked locations (3)" }).closest("section");
    expect(section).not.toBeNull();
    const items = within(section as HTMLElement).getAllByRole("listitem");
    expect(items).toHaveLength(3);
    expect(items[1]).toHaveTextContent("security.txt — discovery path: not found");
    expect(items[2]).toHaveTextContent("subresource: error (timeout)");
  });

  it("shows no banner when the lookup is complete", () => {
    renderReport();
    expect(screen.queryByText(/Lookup incomplete/)).not.toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it.each(["LOOKUP_STATUS_PARTIAL", "LOOKUP_STATUS_FAILED"])(
    "shows the lookup incomplete banner for %s and never claims zero CVEs",
    (lookupStatus) => {
      renderReport({
        lookupStatus,
        components: [component("jquery", "CONFIDENCE_LOW")],
      });

      expect(screen.getByRole("alert")).toHaveTextContent("Lookup incomplete");
      expect(screen.queryByText("No known vulnerabilities.")).not.toBeInTheDocument();
      expect(screen.getByText(/the vulnerability lookup was incomplete/)).toBeInTheDocument();
    },
  );

  it("shows an error, not an empty report, when the target was unreachable", () => {
    renderReport({
      scanStatus: "SCAN_STATUS_TARGET_UNREACHABLE",
      lookupStatus: "LOOKUP_STATUS_UNSPECIFIED",
      components: [],
      checked: [{ url: "https://example.com", reason: "TARGET", result: "RESULT_ERROR", error: "connection refused" }],
    });

    expect(screen.getByRole("alert")).toHaveTextContent("Target unreachable");
    expect(screen.queryByText(/No components were detected/)).not.toBeInTheDocument();
    expect(screen.getByText(/connection refused/)).toBeInTheDocument();
  });

  it("renders vendor strings as text, not markup", () => {
    renderReport({
      components: [
        {
          ...component("evil", "CONFIDENCE_LOW"),
          caveats: ["<img src=x onerror=alert(1)>"],
        },
      ],
    });

    expect(screen.getByText(/<img src=x onerror=alert\(1\)>/)).toBeInTheDocument();
    expect(document.querySelector("img")).toBeNull();
  });
});
