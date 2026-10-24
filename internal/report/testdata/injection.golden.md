# Touchstone scan report

- **Target:** https://vendor.example/?q=&lt;script&gt;alert('xss')&lt;/script&gt;
- **Scan status:** ok
- **Started:** 2026-10-22T09:30:00Z
- **Completed:** 2026-10-22T09:30:12Z
- **Tool version:** 0.0.0-dev\*\*bold\*\* \_em\_ \~\~strike\~\~
- **Vulnerability data as of:** 2026-10-21T18:00:00Z
- **Vulnerability lookup:** complete
- **Requests used:** 0 of 50
- **Schema version:** 1

> **Disclaimer.** Touchstone reports publicly observable evidence only. Findings are graded by confidence and are not proof that a vulnerability is exploitable. Low-confidence findings are inferred from passive fingerprints and are unverified.

## Components

### Low confidence (passive fingerprint; inferred and unverified)

#### &lt;script&gt;alert('xss')&lt;/script&gt;\[click me\](javascript:alert(1)) \*\*bold\*\* \_em\_ \~\~strike\~\~

- **purl:** pkg:npm/\| cell \| &lt;img src=x onerror=alert(1)&gt;
- **CPE:** \`code\` \\escape
- **Caveats:** &amp;lt;b&amp;gt;entity&amp;lt;/b&amp;gt; &amp;amp; &lt;b&gt;tag&lt;/b&gt;
- **Evidence:**
  - fingerprint asset: https://vendor.example/\[click me\](javascript:alert(1)) ( # Injected heading  &lt;iframe src="https://evil.example"&gt;&lt;/iframe&gt;)
- **Vulnerabilities:** 1 vulnerability

| ID | Aliases | KEV | EPSS | CVSS | VEX | Summary |
|---|---|---|---|---|---|---|
| \| cell \| &lt;img src=x onerror=alert(1)&gt; | \*\*bold\*\* \_em\_ \~\~strike\~\~ | no | n/a | n/a | n/a | &lt;script&gt;alert('xss')&lt;/script&gt; # Injected heading  &lt;iframe src="https://evil.example"&gt;&lt;/iframe&gt; |

- **Suppressed by VEX:**
  - \[click me\](javascript:alert(1)): not affected ( # Injected heading  &lt;iframe src="https://evil.example"&gt;&lt;/iframe&gt;)

## Version conflicts

Evidence tiers disagree on the version of these components; deployed may differ from declared.

- **\*\*bold\*\* \_em\_ \~\~strike\~\~:** \| cell \| &lt;img src=x onerror=alert(1)&gt;, \`code\` \\escape
  - none recorded

## Locations checked

| URL | Reason | Result | Error |
|---|---|---|---|
| &lt;script&gt;alert('xss')&lt;/script&gt; | \| cell \| &lt;img src=x onerror=alert(1)&gt; | error |  # Injected heading  &lt;iframe src="https://evil.example"&gt;&lt;/iframe&gt; |

## Sources

| Source | Status | Error |
|---|---|---|
| &amp;lt;b&amp;gt;entity&amp;lt;/b&amp;gt; &amp;amp; &lt;b&gt;tag&lt;/b&gt; | failed | &lt;script&gt;alert('xss')&lt;/script&gt; |
