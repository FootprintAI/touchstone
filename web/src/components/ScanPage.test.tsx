import { readFileSync } from "node:fs";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ScanPage } from "./ScanPage";

const golden = readFileSync(new URL("../../../testdata/report.golden.json", import.meta.url), "utf8");

function mockFetch(status: number, body: string) {
  const fn = vi.fn(async () => new Response(body, { status, headers: { "Content-Type": "application/json" } }));
  vi.stubGlobal("fetch", fn);
  return fn;
}

async function scanUrl(url: string) {
  const user = userEvent.setup();
  render(<ScanPage />);
  await user.type(screen.getByLabelText("Vendor URL"), url);
  await user.click(screen.getByRole("button", { name: "Scan" }));
}

afterEach(() => vi.unstubAllGlobals());

describe("ScanPage", () => {
  it("posts the URL to /v1/scans and renders the report", async () => {
    const fetchMock = mockFetch(200, golden);

    await scanUrl("https://example.com");

    expect(await screen.findByRole("region", { name: "Low confidence" })).toBeInTheDocument();
    expect(screen.getByText("CVE-2020-11022")).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [path, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(path).toBe("/v1/scans");
    expect(init.method).toBe("POST");
    expect(JSON.parse(String(init.body))).toEqual({ url: "https://example.com" });
  });

  it("rejects a non-http URL without calling the server", async () => {
    const fetchMock = mockFetch(200, golden);

    await scanUrl("ftp://example.com");

    expect(await screen.findByRole("alert")).toHaveTextContent("Only http and https");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("shows the server's message when the scan is rejected", async () => {
    mockFetch(400, JSON.stringify({ code: 3, message: "url must be an absolute http(s) URL" }));

    await scanUrl("https://example.com");

    expect(await screen.findByRole("alert")).toHaveTextContent("url must be an absolute http(s) URL");
    expect(screen.queryByRole("article")).not.toBeInTheDocument();
  });

  it("shows an error state when the server is unreachable", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => Promise.reject(new TypeError("Failed to fetch"))));

    await scanUrl("https://example.com");

    expect(await screen.findByRole("alert")).toHaveTextContent("Could not reach the Touchstone server");
    expect(screen.queryByRole("article")).not.toBeInTheDocument();
  });

  it("shows an error state when the response is not a scan report", async () => {
    mockFetch(200, JSON.stringify({ scanStatus: "NOT_A_STATUS" }));

    await scanUrl("https://example.com");

    expect(await screen.findByRole("alert")).toHaveTextContent("not a Touchstone scan report");
  });
});
