package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	touchstonev1 "github.com/FootprintAI/touchstone/gen/go/touchstone/v1"
	"github.com/FootprintAI/touchstone/internal/fetch"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func testServer(t *testing.T) *httptest.Server {
	t.Helper()
	page := fstest.MapFS{"index.html": {Data: []byte("<h1>Touchstone</h1>")}}
	h, err := newHandler(context.Background(), fixedStub(fetch.Options{}), page)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

func TestServeServesPage(t *testing.T) {
	srv := testServer(t)
	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body bytes.Buffer
	body.ReadFrom(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(body.String(), "<h1>Touchstone</h1>") {
		t.Errorf("GET / = %d %q, want the embedded page", resp.StatusCode, body.String())
	}
}

// TestServeScanMatchesGolden posts through grpc-gateway and compares the
// body with the same golden the CLI test and the Vitest suite use.
func TestServeScanMatchesGolden(t *testing.T) {
	srv := testServer(t)
	resp, err := http.Post(srv.URL+"/v1/scans", "application/json", strings.NewReader(`{"url":"https://example.com"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body bytes.Buffer
	body.ReadFrom(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("POST /v1/scans = %d: %s", resp.StatusCode, body.String())
	}
	var got, want touchstonev1.ScanReport
	if err := protojson.Unmarshal(body.Bytes(), &got); err != nil {
		t.Fatalf("response is not a ScanReport: %v\n%s", err, body.String())
	}
	golden, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := protojson.Unmarshal(golden, &want); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(&got, &want) {
		t.Errorf("gateway report differs from %s:\n%s", goldenPath, body.String())
	}
}

func TestServeScanRejectsBadURL(t *testing.T) {
	srv := testServer(t)
	resp, err := http.Post(srv.URL+"/v1/scans", "application/json", strings.NewReader(`{"url":"example.com"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("POST bad url = %d, want 400", resp.StatusCode)
	}
}

func TestServeRejectsBadArgs(t *testing.T) {
	for _, args := range [][]string{
		{"serve", "https://example.com"}, {"serve", "--allow-private"}, {"serve", "--no-such-flag"},
	} {
		if err := run(context.Background(), args, &bytes.Buffer{}, fixedStub); err == nil {
			t.Errorf("run(%q) = nil error, want error", args)
		}
	}
}

func TestServeListensAndStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	out := &syncBuffer{}
	done := make(chan error, 1)
	go func() { done <- run(ctx, []string{"serve", "--addr", "127.0.0.1:0"}, out, fixedStub) }()
	for !strings.Contains(out.String(), "listening on http://127.0.0.1:") {
		select {
		case err := <-done:
			t.Fatalf("serve exited early: %v", err)
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Errorf("serve after cancel: %v", err)
	}
}

// syncBuffer is a bytes.Buffer safe to read while serve writes to it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestServeDefaultAddr(t *testing.T) {
	t.Setenv("TOUCHSTONE_ADDR", "")
	if got := envOr("TOUCHSTONE_ADDR", defaultAddr); got != "127.0.0.1:8080" {
		t.Errorf("default addr = %q, want 127.0.0.1:8080", got)
	}
	t.Setenv("TOUCHSTONE_ADDR", "127.0.0.1:9")
	if got := envOr("TOUCHSTONE_ADDR", defaultAddr); got != "127.0.0.1:9" {
		t.Errorf("env addr = %q", got)
	}
}
