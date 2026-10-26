import { describe, expect, it } from "vitest";
import { SCAN_FORM_FIELDS, buildScanRequest } from "./scanForm";

describe("scan form", () => {
  it("has a URL field and an upload field for the reviewer's SBOM/VEX", () => {
    const byId = Object.fromEntries(SCAN_FORM_FIELDS.map((f) => [f.id, f]));
    expect(byId["sbom-url"]?.type).toBe("url");
    expect(byId["sbom-file"]?.type).toBe("file");
    expect(byId["url"]?.required).toBe(true);
  });

  it("sends sbomUrl and the uploaded file as base64 sbomDocument", async () => {
    const file = new File(['{"bomFormat":"CycloneDX"}'], "sbom.json");
    const body = await buildScanRequest({
      url: " https://vendor.example ",
      sbomUrl: "https://vendor.example/sbom.json",
      sbomFile: file,
    });
    expect(body).toEqual({
      url: "https://vendor.example",
      sbomUrl: "https://vendor.example/sbom.json",
      sbomDocument: btoa('{"bomFormat":"CycloneDX"}'),
    });
  });

  it("omits the optional fields when they are empty", async () => {
    expect(await buildScanRequest({ url: "https://vendor.example", sbomUrl: "" })).toEqual({
      url: "https://vendor.example",
    });
  });

  it("requires the vendor URL", async () => {
    await expect(buildScanRequest({ url: " ", sbomUrl: "" })).rejects.toThrow();
  });
});
