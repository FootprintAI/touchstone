# Touchstone

Paste a vendor's URL, get an evidence-graded CVE report.

Touchstone is for third-party risk reviewers: people who need to know whether
a vendor's public-facing software has known vulnerabilities, without access to
the vendor's systems. It uses the best evidence available about a site and
labels every finding with how sure it is:

| Confidence | Source |
|---|---|
| High | SBOM (and VEX) published by the vendor |
| Medium | The vendor's public source repo, at its latest release |
| Low | Passive fingerprint of the page and the assets it loads |

**Passive only.** Touchstone sends only the requests a browser loading the page
would send, plus well-known discovery paths such as `/.well-known/security.txt`.
It never sends exploit or CVE-test payloads.

**Status:** planning. Nothing is implemented yet. See the PRD at
[`docs/product/touchstone.md`](docs/product/touchstone.md).
Terms are defined in the [glossary](docs/glossary.md).

## License

Apache 2.0, see [LICENSE](LICENSE).
