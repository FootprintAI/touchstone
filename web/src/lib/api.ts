import { fromJson, type JsonValue } from "@bufbuild/protobuf";
import { ScanReportSchema, type ScanReport } from "../gen/touchstone/v1/scan_pb";

/** The ScanService route, served by `touchstone serve` through grpc-gateway. */
export const SCAN_PATH = "/v1/scans";

/** A scan that produced no report. The message is shown to the reviewer. */
export class ScanError extends Error {}

/**
 * POSTs the URL and decodes the reply with the generated parser. Any failure,
 * including a body that is not a ScanReport, becomes a ScanError, so the page
 * never shows a partial or empty report.
 */
export async function requestScan(url: string, fetchFn: typeof fetch = fetch): Promise<ScanReport> {
  let res: Response;
  try {
    res = await fetchFn(SCAN_PATH, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
  } catch {
    throw new ScanError("The scan service could not be reached. Is `touchstone serve` running?");
  }
  const body: unknown = await res.json().catch(() => undefined);
  if (!res.ok) {
    throw new ScanError(gatewayMessage(body) ?? `The scan failed with HTTP ${res.status}.`);
  }
  if (!isJsonValue(body)) {
    throw new ScanError("The scan service replied with something other than JSON.");
  }
  try {
    return fromJson(ScanReportSchema, body);
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    throw new ScanError(`The scan service replied with an unexpected report: ${reason}`);
  }
}

/** True for any value protobuf's JSON parser accepts, checked without a cast. */
export function isJsonValue(value: unknown): value is JsonValue {
  if (value === null || typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    return true;
  }
  if (Array.isArray(value)) {
    return value.every(isJsonValue);
  }
  if (typeof value === "object") {
    // Only plain objects: a Date or class instance is not JSON.
    const proto: unknown = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null) {
      return false;
    }
    return Object.values(value).every(isJsonValue);
  }
  return false;
}

/** The message from a grpc-gateway error body, {"code":…,"message":…}. */
function gatewayMessage(body: unknown): string | undefined {
  if (typeof body === "object" && body !== null && "message" in body && typeof body.message === "string") {
    return body.message;
  }
  return undefined;
}
