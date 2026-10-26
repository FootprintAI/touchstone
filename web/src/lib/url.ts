/** True for an absolute http(s) URL, the only kind ScanService accepts. */
export function isScannableUrl(text: string): boolean {
  try {
    const url = new URL(text);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
}
