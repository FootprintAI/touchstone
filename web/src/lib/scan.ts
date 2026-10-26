import { fromJson, type JsonValue } from "@bufbuild/protobuf";
import { type ScanReport, ScanReportSchema } from "../gen/touchstone/v1/scan_pb";

export class ScanError extends Error {}

/** Returns the message to show for a URL the scan would reject, or null. */
export function validateUrl(raw: string): string | null {
  let u: URL;
  try {
    u = new URL(raw.trim());
  } catch {
    return "Enter an absolute http(s) URL, for example https://vendor.example.";
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") {
    return "Only http and https URLs can be scanned.";
  }
  return null;
}

/** POST /v1/scans (grpc-gateway). Failures throw ScanError with a message fit to show. */
export async function scan(url: string, signal?: AbortSignal): Promise<ScanReport> {
  let res: Response;
  try {
    res = await fetch("/v1/scans", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url.trim() }),
      signal,
    });
  } catch (err) {
    if (err instanceof DOMException && err.name === "AbortError") throw err;
    throw new ScanError("Could not reach the Touchstone server.");
  }

  let body: JsonValue;
  try {
    body = await res.json();
  } catch {
    throw new ScanError(`The server answered ${res.status} with a body that is not JSON.`);
  }
  if (!res.ok) {
    // grpc-gateway errors are {"code": n, "message": "..."}.
    const message =
      typeof body === "object" && body !== null && !Array.isArray(body) && typeof body["message"] === "string"
        ? body["message"]
        : `The scan failed (HTTP ${res.status}).`;
    throw new ScanError(message);
  }
  try {
    return fromJson(ScanReportSchema, body);
  } catch {
    throw new ScanError("The server's response is not a Touchstone scan report.");
  }
}
