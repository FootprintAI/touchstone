import { describe, expect, it } from "vitest";
import { isScannableUrl } from "./url";

describe("isScannableUrl", () => {
  it.each(["https://vendor.example", "http://127.0.0.1:8080/app", "https://vendor.example/a?b=c"])(
    "accepts %s",
    (url) => {
      expect(isScannableUrl(url)).toBe(true);
    },
  );

  it.each(["", "vendor.example", "ftp://vendor.example", "https://", "javascript:alert(1)", "not a url"])(
    "refuses %j",
    (url) => {
      expect(isScannableUrl(url)).toBe(false);
    },
  );
});
