import { describe, expect, it, vi } from "vitest";
import { LookupStatus, ScanStatus } from "../gen/touchstone/v1/scan_pb";
import { goldenText } from "../test/golden";
import { isJsonValue, requestScan, ScanError } from "./api";

function jsonResponse(body: string, status = 200): Response {
  return new Response(body, { status, headers: { "Content-Type": "application/json" } });
}

describe("requestScan", () => {
  it("POSTs the URL to /v1/scans and decodes the reply with the generated parser", async () => {
    const fetchFn = vi.fn<typeof fetch>(async () => jsonResponse(goldenText));

    const report = await requestScan({ url: "https://example.com" }, fetchFn);

    expect(fetchFn).toHaveBeenCalledWith("/v1/scans", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: "https://example.com" }),
    });
    expect(report.scanStatus).toBe(ScanStatus.OK);
    expect(report.lookupStatus).toBe(LookupStatus.COMPLETE);
    expect(report.components[0]?.name).toBe("jquery");
  });

  it("sends a supplied SBOM URL and the uploaded document as base64", async () => {
    const fetchFn = vi.fn<typeof fetch>(async () => jsonResponse(goldenText));

    await requestScan(
      {
        url: "https://example.com",
        sbomUrl: "https://example.com/sbom.json",
        sbomDocument: new TextEncoder().encode("{}"),
      },
      fetchFn,
    );

    expect(fetchFn.mock.calls[0]?.[1]?.body).toBe(
      JSON.stringify({ url: "https://example.com", sbomUrl: "https://example.com/sbom.json", sbomDocument: "e30=" }),
    );
  });

  it("uses the gateway's message for an error reply", async () => {
    const fetchFn = vi.fn<typeof fetch>(async () =>
      jsonResponse('{"code":3,"message":"url must be an absolute http(s) URL","details":[]}', 400),
    );

    await expect(requestScan({ url: "ftp://x" }, fetchFn)).rejects.toThrow("url must be an absolute http(s) URL");
  });

  it("reports the HTTP status when an error reply has no JSON message", async () => {
    const fetchFn = vi.fn<typeof fetch>(async () => new Response("<html>bad gateway</html>", { status: 502 }));

    await expect(requestScan({ url: "https://example.com" }, fetchFn)).rejects.toThrow("HTTP 502");
  });

  it("rejects a reply with a field the contract does not define", async () => {
    const fetchFn = vi.fn<typeof fetch>(async () => jsonResponse('{"schemaVersion":"1","bogusField":true}'));

    await expect(requestScan({ url: "https://example.com" }, fetchFn)).rejects.toBeInstanceOf(ScanError);
  });

  it("turns a network failure into a ScanError, not a raw TypeError", async () => {
    const fetchFn = vi.fn<typeof fetch>(async () => {
      throw new TypeError("Failed to fetch");
    });

    await expect(requestScan({ url: "https://example.com" }, fetchFn)).rejects.toThrow("could not be reached");
  });
});

describe("isJsonValue", () => {
  it.each([null, true, 1, "x", [], [1, "a", null], { a: { b: [1] } }])("accepts %j", (value) => {
    expect(isJsonValue(value)).toBe(true);
  });

  it.each([undefined, () => 1, new Date(0), { a: undefined }, [undefined]])("rejects %s", (value) => {
    expect(isJsonValue(value)).toBe(false);
  });
});
