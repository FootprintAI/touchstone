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
**Status:** S0 (contract first). `go run ./cmd/touchstone scan https://example.com`
prints a canned `ScanReport` from a stub service; it validates against
[`schema/scan-report.v1.json`](schema/scan-report.v1.json). Add `--format md`
to get the same report as Markdown for a vendor-review ticket: every
vendor string is escaped, and a report whose vulnerability lookup did not
complete says "lookup incomplete" instead of showing a count. The API contract
lives in [`proto/touchstone/v1/scan.proto`](proto/touchstone/v1/scan.proto);
run `make generate` (requires [buf](https://buf.build)) to regenerate the Go,
TypeScript, OpenAPI and JSON Schema outputs under `gen/`, `web/src/gen/`,
`openapi/` and `schema/`. Generated code is committed and CI fails if it is
stale. `make test` and `make web-test` run the Go and web suites. See the design at
[`docs/architecture/touchstone.md`](docs/architecture/touchstone.md) and
the PRD at [`docs/product/touchstone.md`](docs/product/touchstone.md).

## License

Apache 2.0, see [LICENSE](LICENSE).
