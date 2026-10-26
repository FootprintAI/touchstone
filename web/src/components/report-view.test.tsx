import { cleanup, render, screen, within } from "@testing-library/react";
import { create } from "@bufbuild/protobuf";
import { afterEach, describe, expect, it } from "vitest";
import {
  CheckedLocation_Result,
  CheckedLocationSchema,
  Confidence,
  ComponentSchema,
  LookupStatus,
  VulnerabilitySchema,
} from "../gen/touchstone/v1/scan_pb";
import { goldenReport } from "../test/golden";
import { ReportView } from "./report-view";

afterEach(cleanup);

function lowTier(): HTMLElement {
  return screen.getByRole("region", { name: "Low confidence" });
}

describe("ReportView", () => {
  it("shows the jQuery component under Low confidence with its CVE list", () => {
    render(<ReportView report={goldenReport()} />);

    const low = lowTier();
    expect(within(low).getByRole("heading", { name: /jquery/ })).toBeTruthy();
    expect(within(low).getByText("1.12.4")).toBeTruthy();
    expect(within(low).getByText("CVE-2020-11022")).toBeTruthy();
    expect(within(low).getByText("Also known as GHSA-gxr4-xjj5-5px2")).toBeTruthy();
    expect(within(low).getByText("Potential XSS vulnerability in jQuery.htmlPrefilter")).toBeTruthy();
  });

  it("groups components under their confidence tier and says when a tier is empty", () => {
    const report = goldenReport();
    report.components.push(
      create(ComponentSchema, { name: "lodash", version: "4.17.21", confidence: Confidence.HIGH }),
      create(ComponentSchema, { name: "react", version: "18.2.0", confidence: Confidence.MEDIUM }),
    );
    render(<ReportView report={report} />);

    const high = screen.getByRole("region", { name: "High confidence" });
    const medium = screen.getByRole("region", { name: "Medium confidence" });
    expect(within(high).getByText("lodash")).toBeTruthy();
    expect(within(high).queryByText("react")).toBeNull();
    expect(within(medium).getByText("react")).toBeTruthy();
    expect(within(medium).queryByText("lodash")).toBeNull();
    expect(within(lowTier()).getByText("jquery")).toBeTruthy();
  });

  it("keeps a component with no confidence in an Unclassified section", () => {
    const report = goldenReport();
    report.components.push(create(ComponentSchema, { name: "mystery", version: "1.0.0" }));
    render(<ReportView report={report} />);

    expect(within(screen.getByRole("region", { name: "Unclassified" })).getByText(/mystery/)).toBeTruthy();
  });

  it("shows the lookup-incomplete banner and no vulnerability count when the lookup is PARTIAL", () => {
    const report = goldenReport();
    report.lookupStatus = LookupStatus.PARTIAL;
    render(<ReportView report={report} />);

    const banner = screen.getByRole("alert");
    expect(within(banner).getByText("Lookup incomplete")).toBeTruthy();
    expect(within(lowTier()).getByRole("heading", { name: "Vulnerabilities" })).toBeTruthy();
    expect(screen.queryByText(/Vulnerabilities \(1\)/)).toBeNull();
    expect(within(lowTier()).getByText("CVE-2020-11022")).toBeTruthy();
  });

  it("treats a FAILED or unspecified lookup as incomplete too", () => {
    for (const lookupStatus of [LookupStatus.FAILED, LookupStatus.UNSPECIFIED]) {
      const report = goldenReport();
      report.lookupStatus = lookupStatus;
      const { unmount } = render(<ReportView report={report} />);
      expect(screen.getByRole("alert")).toBeTruthy();
      unmount();
    }
  });

  it("shows no banner and the count when the lookup is COMPLETE", () => {
    render(<ReportView report={goldenReport()} />);

    expect(screen.queryByRole("alert")).toBeNull();
    expect(within(lowTier()).getByRole("heading", { name: "Vulnerabilities (1)" })).toBeTruthy();
  });

  it("lists the evidence behind each finding", () => {
    render(<ReportView report={goldenReport()} />);

    const evidence = within(lowTier()).getByText("Evidence (1)");
    expect(evidence.closest("details")).toBeTruthy();
    expect(within(lowTier()).getByText("fingerprint asset")).toBeTruthy();
    expect(within(lowTier()).getByText("https://example.com")).toBeTruthy();
    expect(within(lowTier()).getByText("(jquery-1.12.4.min.js)")).toBeTruthy();
  });

  it("lists every checked location with its result", () => {
    const report = goldenReport();
    report.checked.push(
      create(CheckedLocationSchema, {
        url: "https://example.com/.well-known/security.txt",
        reason: "DISCOVERY_PATH",
        result: CheckedLocation_Result.NOT_FOUND,
      }),
      create(CheckedLocationSchema, {
        url: "https://example.com/admin",
        reason: "TARGET",
        result: CheckedLocation_Result.REFUSED,
        error: "not an allowed reason",
      }),
    );
    report.requestsUsed = 3;
    render(<ReportView report={report} />);

    const checked = screen.getByRole("region", { name: "Checked locations" });
    expect(within(checked).getByText("3 of 50 requests used.")).toBeTruthy();
    expect(within(checked).getByText("https://example.com/.well-known/security.txt")).toBeTruthy();
    expect(within(checked).getByText("not found")).toBeTruthy();
    expect(within(checked).getByText("refused")).toBeTruthy();
    expect(within(checked).getByText("not an allowed reason")).toBeTruthy();
  });

  it("lists a component's CVEs in the order the server sent them", () => {
    // Neither ascending nor descending, so a sort or a reverse in the component fails.
    const report = goldenReport();
    report.components.push(
      create(ComponentSchema, {
        name: "openssl",
        version: "1.1.1",
        confidence: Confidence.LOW,
        vulnerabilities: [
          create(VulnerabilitySchema, { id: "CVE-2024-0002" }),
          create(VulnerabilitySchema, { id: "CVE-2023-0001" }),
          create(VulnerabilitySchema, { id: "CVE-2025-0003" }),
        ],
      }),
    );
    render(<ReportView report={report} />);

    const card = within(lowTier()).getByRole("heading", { name: /openssl/ }).closest("article");
    expect(card).toBeTruthy();
    const ids = within(card as HTMLElement)
      .getAllByText(/^CVE-/)
      .map((el) => el.textContent);
    expect(ids).toEqual(["CVE-2024-0002", "CVE-2023-0001", "CVE-2025-0003"]);
  });

  it("shows the disclaimer from the report", () => {
    const report = goldenReport();
    render(<ReportView report={report} />);

    expect(screen.getByText(report.disclaimer)).toBeTruthy();
  });
});
