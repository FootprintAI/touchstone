# Touchstone scan report

- **Target:** https://vendor.example/
- **Scan status:** ok
- **Started:** 2026-10-22T09:30:00Z
- **Completed:** 2026-10-22T09:30:12Z
- **Tool version:** 0.0.0-dev
- **Vulnerability data as of:** 2026-10-21T18:00:00Z
- **Vulnerability lookup:** lookup incomplete (partial: at least one vulnerability source failed)
- **Requests used:** 2 of 50
- **Schema version:** 1

> **Disclaimer.** Touchstone reports publicly observable evidence only. Findings are graded by confidence and are not proof that a vulnerability is exploitable. Low-confidence findings are inferred from passive fingerprints and are unverified.

## Components

### Low confidence (passive fingerprint; inferred and unverified)

#### jquery 3.4.1

- **purl:** pkg:npm/jquery@3.4.1
- **Evidence:**
  - fingerprint asset: https://vendor.example/static/jquery-3.4.1.min.js (jquery-3.4.1.min.js)
- **Vulnerabilities:** lookup incomplete

| ID | Aliases | KEV | EPSS | CVSS | VEX | Summary |
|---|---|---|---|---|---|---|
| CVE-2020-11022 |  | no | n/a | n/a | n/a | Potential XSS vulnerability in jQuery.htmlPrefilter |

#### Apache 2.4.38

- **CPE:** cpe:2.3:a:apache:http\_server:2.4.38:\*:\*:\*:\*:\*:\*:\*
- **Caveats:** MAY\_BE\_BACKPORTED
- **Evidence:**
  - fingerprint header: https://vendor.example/ (Server: Apache/2.4.38)
- **Vulnerabilities:** lookup incomplete

## Locations checked

No locations were recorded.

## Sources

| Source | Status | Error |
|---|---|---|
| osv | ok |  |
| nvd | failed | Get "https://services.nvd.nist.gov/rest/json/cves/2.0": 503 Service Unavailable |
