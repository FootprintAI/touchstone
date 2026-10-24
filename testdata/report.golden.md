# Touchstone scan report

- **Target:** https://example.com
- **Scan status:** ok
- **Started:** 2026-10-22T00:00:00Z
- **Completed:** 2026-10-22T00:00:00Z
- **Tool version:** 0.0.0-dev
- **Vulnerability data as of:** 2026-10-22T00:00:00Z
- **Vulnerability lookup:** complete
- **Requests used:** 0 of 50
- **Schema version:** 1

> **Disclaimer.** Touchstone reports publicly observable evidence only. Findings are graded by confidence and are not proof that a vulnerability is exploitable. Low-confidence findings are inferred from passive fingerprints and are unverified.

## Components

### Low confidence (passive fingerprint; inferred and unverified)

#### jquery 1.12.4

- **purl:** pkg:npm/jquery@1.12.4
- **Caveats:** CANNED\_STUB\_REPORT
- **Evidence:**
  - fingerprint asset: https://example.com (jquery-1.12.4.min.js)
- **Vulnerabilities:** 1 vulnerability

| ID | Aliases | KEV | EPSS | CVSS | VEX | Summary |
|---|---|---|---|---|---|---|
| CVE-2020-11022 | GHSA-gxr4-xjj5-5px2 | no | 0.0123 | 6.1 | n/a | Potential XSS vulnerability in jQuery.htmlPrefilter |

## Locations checked

No locations were recorded.

## Sources

| Source | Status | Error |
|---|---|---|
| stub | ok |  |
