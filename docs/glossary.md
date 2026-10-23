# Glossary

Terms used in the [README](../README.md) and the PRD
([`docs/product/touchstone.md`](product/touchstone.md)). Every entry is taken
from those two documents. Where neither defines a term, the entry says so and
only records how the term is used. Touchstone is in planning: nothing below is
implemented yet.

## Confidence levels

Every finding is labelled with how sure Touchstone is about it, based on where
the evidence came from (README table).

- **High:** SBOM (and VEX) published by the vendor. The PRD adds that this
  means "the vendor declared it", and that an SBOM or VEX supplied by the
  reviewer is also rated High.
- **Medium:** The vendor's public source repo, at its latest release. The PRD
  adds: "declared source, may differ from what's deployed".
- **Low:** Passive fingerprint of the page and the assets it loads. The PRD
  adds: "inferred from outside".

## Terms

- **Backport:** Not defined in the README or the PRD. The PRD uses it for the
  problem that "distro backports keep old version numbers", which causes false
  positives, and plans a "may be backported by the OS vendor" caveat on
  server-banner versions.
- **CSAF:** Not defined in the README or the PRD. The PRD plans to check the
  `CSAF:` field of `security.txt` and `/.well-known/csaf/provider-metadata.json`,
  and lists CSAF 2.0 VEX as one VEX format to parse.
- **EPSS:** Not defined in the README or the PRD. The PRD plans for each CVE to
  carry an EPSS score, with CVEs sorted KEV first, then by EPSS descending.
- **KEV:** Not defined in the README or the PRD. The PRD refers to it as the
  "CISA KEV flag" carried by each CVE, and lists KEV as one of the CVE data
  sources.
- **OSV:** Not defined in the README or the PRD. The PRD plans to match
  components that have a package URL (purl) against OSV.dev, and names OSV as
  one of the CVE data sources.
- **Passive only:** Touchstone sends only the requests a browser loading the
  page would send, plus well-known discovery paths such as
  `/.well-known/security.txt`. It never sends exploit or CVE-test payloads
  (README). The PRD adds that it never brute-forces paths and identifies itself
  with a descriptive `User-Agent`.
- **SBOM:** Not defined in the README or the PRD. Both use a vendor-published
  SBOM as the source of High-confidence findings; the PRD names the CycloneDX
  1.5+ JSON and SPDX 2.3 JSON formats.
- **VEX:** Not defined in the README or the PRD. The PRD uses it for the
  vendor's declaration that a CVE is `not_affected` or `fixed` for a component,
  which suppresses that CVE, and calls VEX "the only exploitability input". It
  names CycloneDX VEX, OpenVEX and CSAF 2.0 VEX as formats.
