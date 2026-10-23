package pipeline

import (
	"context"
	"errors"
	"testing"
)

func TestFakeEvidenceSourceReturnsConfiguredComponents(t *testing.T) {
	want := []Component{{Name: "jquery", Version: "1.12.4", Confidence: "LOW"}}
	s := &FakeEvidenceSource{SourceName: "fingerprint", Components: want}

	if got := s.Name(); got != "fingerprint" {
		t.Fatalf("Name: got %q, want %q", got, "fingerprint")
	}

	got, err := s.Collect(context.Background(), "https://example.com")
	if err != nil {
		t.Fatalf("Collect: unexpected error: %v", err)
	}
	if len(got) != 1 || got[0].Name != want[0].Name {
		t.Fatalf("Collect: got %+v, want %+v", got, want)
	}
}

func TestFakeEvidenceSourceReturnsConfiguredError(t *testing.T) {
	wantErr := errors.New("source unavailable")
	s := &FakeEvidenceSource{SourceName: "repo", Err: wantErr}

	if _, err := s.Collect(context.Background(), "https://example.com"); !errors.Is(err, wantErr) {
		t.Fatalf("Collect: got error %v, want %v", err, wantErr)
	}
}
