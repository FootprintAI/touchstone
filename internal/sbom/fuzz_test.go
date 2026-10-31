package sbom

import (
	"errors"
	"testing"
)

// Each fuzz target feeds arbitrary bytes to one parser. A parser may return
// an error, but only ErrUnknownFormat or a *ParseError, and never panic.
// Run one with: go test -run '^$' -fuzz FuzzCycloneDX -fuzztime 30s ./internal/sbom

func fuzzParser(f *testing.F, parse func([]byte) (*Document, error), seeds ...string) {
	for _, s := range seeds {
		f.Add(readFixture(f, s))
	}
	f.Add([]byte(""))
	f.Add([]byte("{}"))
	f.Fuzz(func(t *testing.T, data []byte) {
		doc, err := parse(data)
		if err != nil {
			var pe *ParseError
			if !errors.As(err, &pe) && !errors.Is(err, ErrUnknownFormat) {
				t.Fatalf("untyped error: %v", err)
			}
			return
		}
		if doc == nil {
			t.Fatal("nil document with nil error")
		}
	})
}

func FuzzCycloneDX(f *testing.F) {
	fuzzParser(f, parseCycloneDX, "cyclonedx-1.5.json", "cyclonedx-vex-1.6.json")
}

func FuzzSPDX(f *testing.F) { fuzzParser(f, parseSPDX, "spdx-2.3.json") }

func FuzzOpenVEX(f *testing.F) { fuzzParser(f, parseOpenVEX, "openvex.json") }

func FuzzCSAF(f *testing.F) { fuzzParser(f, ParseCSAF, "csaf-vex.json") }

func FuzzParse(f *testing.F) {
	fuzzParser(f, Parse, "cyclonedx-vex-1.6.json", "spdx-2.3.json", "openvex.json", "csaf-vex.json")
}
