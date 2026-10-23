package vuln

import (
	"context"
	"errors"
	"testing"
)

func TestFakeSourceReturnsConfiguredFindings(t *testing.T) {
	want := []Finding{{ID: "CVE-2021-1234", Summary: "example"}}
	s := &FakeSource{SourceName: "osv", Findings: want}

	if got := s.Name(); got != "osv" {
		t.Fatalf("Name: got %q, want %q", got, "osv")
	}

	got, err := s.Lookup(context.Background(), []Query{{Purl: "pkg:npm/example@1.0.0"}})
	if err != nil {
		t.Fatalf("Lookup: unexpected error: %v", err)
	}
	if len(got) != 1 || got[0].ID != want[0].ID {
		t.Fatalf("Lookup: got %+v, want %+v", got, want)
	}
}

func TestFakeSourceReturnsConfiguredError(t *testing.T) {
	wantErr := errors.New("osv down")
	s := &FakeSource{SourceName: "osv", Err: wantErr}

	if _, err := s.Lookup(context.Background(), nil); !errors.Is(err, wantErr) {
		t.Fatalf("Lookup: got error %v, want %v", err, wantErr)
	}
}

func TestFakeEnricherReturnsOnlyKnownIDs(t *testing.T) {
	e := &FakeEnricher{
		EnricherName: "kev",
		Enrichments: map[string]Enrichment{
			"CVE-2021-1234": {KEV: true},
		},
	}

	got, err := e.Enrich(context.Background(), []string{"CVE-2021-1234", "CVE-9999-0000"})
	if err != nil {
		t.Fatalf("Enrich: unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("Enrich: got %d entries, want 1", len(got))
	}
	if !got["CVE-2021-1234"].KEV {
		t.Fatalf("Enrich: CVE-2021-1234 KEV = false, want true")
	}
}
