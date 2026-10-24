# Touchstone scan report

- **Target:** https://vendor.example/
- **Scan status:** ok
- **Started:** 2026-10-22T09:30:00Z
- **Completed:** 2026-10-22T09:30:12Z
- **Tool version:** 0.0.0-dev
- **Vulnerability data as of:** 2026-10-21T18:00:00Z
- **Vulnerability lookup:** complete
- **Requests used:** 3 of 50
- **Schema version:** 1

> **Disclaimer.** Touchstone reports publicly observable evidence only. Findings are graded by confidence and are not proof that a vulnerability is exploitable. Low-confidence findings are inferred from passive fingerprints and are unverified.

## Components

### High confidence (declared by the vendor in an SBOM or VEX)

#### lodash 4.17.20

- **purl:** pkg:npm/lodash@4.17.20
- **Evidence:**
  - sbom published: https://vendor.example/.well-known/sbom.cdx.json
- **Vulnerabilities:** 1 vulnerability

| ID | Aliases | KEV | EPSS | CVSS | VEX | Summary |
|---|---|---|---|---|---|---|
| CVE-2021-23337 | GHSA-35jh-r3h4-6jhm | yes | 0.97 | 9.8 | n/a | Command injection via template |

- **Suppressed by VEX:**
  - CVE-2020-28500: not affected (vulnerable\_code\_not\_in\_execute\_path)

### Medium confidence (public source repo at its latest release; may differ from what is deployed)

#### express 4.18.2

- **purl:** pkg:npm/express@4.18.2
- **Caveats:** DEFAULT\_BRANCH\_NOT\_RELEASE
- **Evidence:**
  - repo lockfile: github.com/vendor/app@v1.2.0:package-lock.json
- **Vulnerabilities:** no known vulnerabilities

### Low confidence (passive fingerprint; inferred and unverified)

#### jquery 3.4.1

- **purl:** pkg:npm/jquery@3.4.1
- **Evidence:**
  - fingerprint asset: https://vendor.example/static/jquery-3.4.1.min.js (jquery-3.4.1.min.js)
- **Vulnerabilities:** 1 vulnerability

| ID | Aliases | KEV | EPSS | CVSS | VEX | Summary |
|---|---|---|---|---|---|---|
| CVE-2020-11022 | GHSA-gxr4-xjj5-5px2 | no | n/a | n/a | n/a | Potential XSS vulnerability in jQuery.htmlPrefilter |

#### Apache 2.4.38

- **CPE:** cpe:2.3:a:apache:http\_server:2.4.38:\*:\*:\*:\*:\*:\*:\*
- **Caveats:** MAY\_BE\_BACKPORTED
- **Evidence:**
  - fingerprint header: https://vendor.example/ (Server: Apache/2.4.38 (Debian))
- **Vulnerabilities:** no known vulnerabilities

## Version conflicts

Evidence tiers disagree on the version of these components; deployed may differ from declared.

- **pkg:npm/jquery:** 3.4.1, 3.7.1
  - fingerprint asset: https://vendor.example/static/jquery-3.4.1.min.js (jquery-3.4.1.min.js)
  - sbom published: https://vendor.example/.well-known/sbom.cdx.json (pkg:npm/jquery@3.7.1)

## Locations checked

| URL | Reason | Result | Error |
|---|---|---|---|
| https://vendor.example/ | TARGET | found |  |
| https://vendor.example/.well-known/security.txt | DISCOVERY\_PATH | not found |  |
| https://vendor.example/static/jquery-3.4.1.min.js | SUBRESOURCE | found |  |

## Sources

| Source | Status | Error |
|---|---|---|
| osv | ok |  |
| nvd | ok |  |
| kev | ok |  |
| epss | ok |  |
