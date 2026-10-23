package fetch

import (
	"context"
	"errors"
	"testing"
)

func TestFakeReturnsConfiguredResponse(t *testing.T) {
	f := NewFake()
	want := &Response{URL: "https://example.com/", StatusCode: 200, Body: []byte("ok")}
	f.SetResponse("https://example.com/", want)

	got, err := f.Get(context.Background(), "https://example.com/", ReasonTarget)
	if err != nil {
		t.Fatalf("Get: unexpected error: %v", err)
	}
	if got != want {
		t.Fatalf("Get: got %+v, want %+v", got, want)
	}

	if len(f.Calls) != 1 {
		t.Fatalf("Calls: got %d, want 1", len(f.Calls))
	}
	if f.Calls[0] != (Call{URL: "https://example.com/", Reason: ReasonTarget}) {
		t.Fatalf("Calls[0]: got %+v", f.Calls[0])
	}
}

func TestFakeReturnsConfiguredError(t *testing.T) {
	f := NewFake()
	wantErr := errors.New("refused")
	f.SetError("https://example.com/private", wantErr)

	_, err := f.Get(context.Background(), "https://example.com/private", ReasonSubresource)
	if !errors.Is(err, wantErr) {
		t.Fatalf("Get: got error %v, want %v", err, wantErr)
	}
}

func TestFakeUnconfiguredURLErrors(t *testing.T) {
	f := NewFake()
	if _, err := f.Get(context.Background(), "https://unknown.example/", ReasonTarget); err == nil {
		t.Fatal("Get: want error for unconfigured URL, got nil")
	}
}
