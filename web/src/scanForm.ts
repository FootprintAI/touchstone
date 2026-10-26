import { create, toJson, type JsonValue } from "@bufbuild/protobuf";
import { ScanRequestSchema } from "./gen/touchstone/v1/scan_pb";

// The reviewer-supplied SBOM/VEX inputs (design decision D1): a vendor
// questionnaire answer is usually the only way to get a High-tier SBOM.
// An uploaded file is capped like a fetched response (2 MiB).
export const MAX_SBOM_BYTES = 2 << 20;

export const SCAN_FORM_FIELDS = [
  { id: "url", label: "Vendor URL", type: "url", required: true },
  { id: "sbom-url", label: "SBOM/VEX URL (optional)", type: "url", required: false },
  { id: "sbom-file", label: "SBOM/VEX file (optional)", type: "file", required: false },
] as const;

export interface ScanFormValues {
  url: string;
  sbomUrl: string;
  sbomFile?: File | undefined;
}

// buildScanRequest returns the JSON body for POST /v1/scans.
export async function buildScanRequest(v: ScanFormValues): Promise<JsonValue> {
  const url = v.url.trim();
  if (url === "") throw new Error("Enter the vendor URL to scan.");
  if (v.sbomFile && v.sbomFile.size > MAX_SBOM_BYTES) {
    throw new Error(`The SBOM/VEX file is larger than ${MAX_SBOM_BYTES} bytes.`);
  }
  const msg = create(ScanRequestSchema, {
    url,
    sbomUrl: v.sbomUrl.trim(),
    sbomDocument: v.sbomFile ? new Uint8Array(await v.sbomFile.arrayBuffer()) : new Uint8Array(),
  });
  return toJson(ScanRequestSchema, msg);
}

// renderScanForm builds the scan form: the vendor URL, plus a URL field
// and an upload field for a reviewer-supplied SBOM/VEX.
export function renderScanForm(
  doc: Document,
  onSubmit: (values: ScanFormValues) => void,
): HTMLFormElement {
  const form = doc.createElement("form");
  for (const f of SCAN_FORM_FIELDS) {
    const label = doc.createElement("label");
    label.htmlFor = f.id;
    label.textContent = f.label;
    const input = doc.createElement("input");
    input.id = f.id;
    input.name = f.id;
    input.type = f.type;
    input.required = f.required;
    if (f.type === "file") input.accept = ".json,application/json";
    form.append(label, input);
  }
  const button = doc.createElement("button");
  button.type = "submit";
  button.textContent = "Scan";
  form.append(button);
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const field = (id: string) => form.querySelector<HTMLInputElement>(`#${id}`);
    onSubmit({
      url: field("url")?.value ?? "",
      sbomUrl: field("sbom-url")?.value ?? "",
      sbomFile: field("sbom-file")?.files?.[0],
    });
  });
  return form;
}
