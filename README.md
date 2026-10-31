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

### Discovery and a supplied SBOM/VEX

Every scan checks `/.well-known/security.txt` (then `/security.txt`),
`/.well-known/csaf/provider-metadata.json` and `/.well-known/tea` on the
target's origin. It follows each `CSAF:` field and the provider metadata's
public ROLIE feeds to the five newest CSAF documents, and reads the products
of those that are CSAF VEX as High-confidence components. `/.well-known/tea`
is recorded in `checked` but not queried. Every request is in the report's
`checked` list.

If you already have the vendor's SBOM or VEX (CycloneDX, SPDX 2.3, OpenVEX
or CSAF, as JSON), pass it in. Its components are High confidence with
`SBOM_SUPPLIED` evidence:

```sh
touchstone scan --sbom vendor-sbom.json https://vendor.example
touchstone scan --sbom-url https://vendor.example/sbom.json https://vendor.example
```

The web page has the same inputs: an SBOM/VEX URL (`sbom_url`), and a file
upload or pasted text (`sbom_document`). The document is capped at 2 MiB; the
form rejects a larger one before sending. Pasted text is used instead of a
chosen file. The report shows the supplied components under High confidence
with `SBOM_SUPPLIED` evidence.

### Web page: `touchstone serve`

`touchstone serve` runs the web page and `POST /v1/scans` on one port.

```sh
make web-build          # exports the page to web/out
go build ./cmd/touchstone
./touchstone serve --addr 127.0.0.1:8080
```

- `--addr host:port` sets the listen address. The default is `127.0.0.1:8080`.
- `TOUCHSTONE_ADDR` sets the same address from the environment. The flag wins when both are set.
- Run `make web-build` before `go build`. The page is embedded at build time, so a binary built
  without it serves 404 at `/`.
- The server has no authentication. When the address is not loopback (for example `0.0.0.0:8080`
  or `:8080`), `serve` prints a warning on stderr. Bind to `127.0.0.1` unless you mean to expose it.

## License

Apache 2.0, see [LICENSE](LICENSE).
