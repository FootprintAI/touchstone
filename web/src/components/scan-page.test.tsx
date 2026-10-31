import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { goldenText } from "../test/golden";
import { ScanPage } from "./scan-page";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function stubFetch(impl: () => Promise<Response>) {
  const fn = vi.fn<typeof fetch>(impl);
  vi.stubGlobal("fetch", fn);
  return fn;
}

function scanFor(url: string) {
  fireEvent.change(screen.getByLabelText("Vendor URL"), { target: { value: url } });
  fireEvent.click(screen.getByRole("button", { name: "Scan" }));
}

describe("ScanPage", () => {
  it("refuses a value that is not an http(s) URL without sending a request", () => {
    const fetchMock = stubFetch(async () => new Response(goldenText));
    render(<ScanPage />);

    scanFor("vendor.example");

    expect(screen.getByText("Enter an absolute http:// or https:// URL.")).toBeTruthy();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("posts the URL and renders the report, with the jQuery component under Low confidence", async () => {
    const fetchMock = stubFetch(async () => new Response(goldenText, { status: 200 }));
    render(<ScanPage />);

    scanFor("  https://example.com  ");

    const low = await screen.findByRole("region", { name: "Low confidence" });
    expect(within(low).getByText("CVE-2020-11022")).toBeTruthy();
    expect(fetchMock).toHaveBeenCalledWith("/v1/scans", expect.objectContaining({ method: "POST" }));
    expect(fetchMock.mock.calls[0]?.[1]?.body).toBe(JSON.stringify({ url: "https://example.com" }));
  });

  it("sends a supplied SBOM/VEX URL with the scan", async () => {
    const fetchMock = stubFetch(async () => new Response(goldenText, { status: 200 }));
    render(<ScanPage />);

    fireEvent.change(screen.getByLabelText("SBOM/VEX URL"), { target: { value: " https://example.com/sbom.json " } });
    scanFor("https://example.com");

    await screen.findByRole("region", { name: "Low confidence" });
    expect(fetchMock.mock.calls[0]?.[1]?.body).toBe(
      JSON.stringify({ url: "https://example.com", sbomUrl: "https://example.com/sbom.json" }),
    );
  });

  it("refuses an SBOM/VEX URL that is not http(s) without sending a request", () => {
    const fetchMock = stubFetch(async () => new Response(goldenText));
    render(<ScanPage />);

    fireEvent.change(screen.getByLabelText("SBOM/VEX URL"), { target: { value: "file:///sbom.json" } });
    scanFor("https://example.com");

    expect(screen.getByText(/URL for the SBOM\/VEX/)).toBeTruthy();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("uploads a chosen SBOM/VEX file as sbomDocument", async () => {
    const fetchMock = stubFetch(async () => new Response(goldenText, { status: 200 }));
    render(<ScanPage />);

    const file = new File(["{}"], "sbom.json", { type: "application/json" });
    fireEvent.change(screen.getByLabelText("SBOM/VEX file"), { target: { files: [file] } });
    scanFor("https://example.com");

    await screen.findByRole("region", { name: "Low confidence" });
    expect(fetchMock.mock.calls[0]?.[1]?.body).toBe(JSON.stringify({ url: "https://example.com", sbomDocument: "e30=" }));
  });

  it("refuses an SBOM/VEX file over 2 MiB without sending a request", () => {
    const fetchMock = stubFetch(async () => new Response(goldenText));
    render(<ScanPage />);

    const big = new File([new Uint8Array(2 * 1024 * 1024 + 1)], "big-sbom.json", { type: "application/json" });
    fireEvent.change(screen.getByLabelText("SBOM/VEX file"), { target: { files: [big] } });
    scanFor("https://example.com");

    expect(screen.getByText(/too large/)).toBeTruthy();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("shows the gateway's message as an error, not an empty report", async () => {
    stubFetch(
      async () => new Response('{"code":13,"message":"internal error","details":[]}', { status: 500 }),
    );
    render(<ScanPage />);

    scanFor("https://example.com");

    expect((await screen.findByRole("alert")).textContent).toContain("internal error");
    expect(screen.queryByRole("region", { name: "Low confidence" })).toBeNull();
  });

  it("shows an error when touchstone serve cannot be reached", async () => {
    stubFetch(async () => {
      throw new TypeError("Failed to fetch");
    });
    render(<ScanPage />);

    scanFor("https://example.com");

    expect((await screen.findByRole("alert")).textContent).toContain("could not be reached");
  });

  it("shows an error, not an empty report, when the target was unreachable", async () => {
    const unreachable = JSON.stringify({
      schemaVersion: "1",
      targetUrl: "https://example.com",
      scanStatus: "SCAN_STATUS_TARGET_UNREACHABLE",
      lookupStatus: "LOOKUP_STATUS_COMPLETE",
    });
    stubFetch(async () => new Response(unreachable));
    render(<ScanPage />);

    scanFor("https://example.com");

    expect((await screen.findByRole("alert")).textContent).toContain("could not be reached");
    expect(screen.queryByRole("region", { name: "Low confidence" })).toBeNull();
    expect(screen.queryByRole("region", { name: "Checked locations" })).toBeNull();
  });

  it("disables the button while the scan runs", async () => {
    let finish: (r: Response) => void = () => {};
    stubFetch(() => new Promise<Response>((resolve) => (finish = resolve)));
    render(<ScanPage />);

    scanFor("https://example.com");

    expect(screen.getByRole("button", { name: "Scanning…" }).hasAttribute("disabled")).toBe(true);
    finish(new Response(goldenText));
    expect(await screen.findByRole("region", { name: "Low confidence" })).toBeTruthy();
  });
});
