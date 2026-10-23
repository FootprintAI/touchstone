.PHONY: generate lint breaking test

# Requires buf (https://buf.build): regenerates gen/, web/src/gen/,
# openapi/ and schema/ from proto/touchstone/v1/scan.proto. The
# jsonschema plugin names its output after the message; rename/symlink
# the ScanReport schema to schema/scan-report.v1.json if the plugin
# version in use doesn't do so itself.
generate:
	buf dep update
	buf generate

lint:
	buf lint

breaking:
	buf breaking --against 'https://github.com/FootprintAI/touchstone.git#branch=main'

test:
	go vet ./...
	go test ./...
