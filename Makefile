.PHONY: generate lint breaking test fuzz web-test web-build

# Requires buf (https://buf.build): regenerates gen/, web/src/gen/,
# openapi/ and schema/ from proto/touchstone/v1/scan.proto, using the
# googleapis version pinned in buf.lock (`buf dep update` to bump it).
# The jsonschema plugin names its output after the message, so the
# published ScanReport schema is moved to its stable, documented name.
generate:
	buf generate
	mv schema/touchstone.v1.ScanReport.jsonschema.bundle.json schema/scan-report.v1.json

lint:
	buf lint

breaking:
	buf breaking --against '.git#branch=main'

test:
	go vet ./...
	staticcheck ./...
	go test ./...

# Runs each SBOM/VEX parser's fuzz target for FUZZTIME (default 20s).
FUZZTIME ?= 20s
fuzz:
	for t in FuzzCycloneDX FuzzSPDX FuzzOpenVEX FuzzCSAF FuzzParse; do \
		go test -run '^$$' -fuzz "^$$t$$" -fuzztime $(FUZZTIME) ./internal/sbom || exit 1; \
	done

web-test:
	cd web && npm install --no-package-lock && npx tsc --noEmit && npx vitest run

# Exports the page to web/out, which web/embed.go embeds into touchstone serve.
# Build it before `go build ./cmd/touchstone`.
web-build:
	cd web && npm install --no-package-lock && npx next build
