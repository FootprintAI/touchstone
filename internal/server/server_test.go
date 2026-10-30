package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	touchstonev1 "github.com/FootprintAI/touchstone/gen/go/touchstone/v1"
	"github.com/FootprintAI/touchstone/internal/service"
)

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	return newServerFor(t, &service.Stub{Now: func() time.Time { return time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC) }})
}

func newServerFor(t *testing.T, svc touchstonev1.ScanServiceServer) *httptest.Server {
	t.Helper()
	static := fstest.MapFS{"index.html": {Data: []byte("<html>touchstone page</html>")}}
	h, err := New(context.Background(), svc, static)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

func post(t *testing.T, srv *httptest.Server, body string) (int, string) {
	t.Helper()
	resp, err := http.Post(srv.URL+"/v1/scans", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestServesPageAtRoot(t *testing.T) {
	srv := newTestServer(t)
	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "touchstone page") {
		t.Fatalf("GET /: status %d, body %q", resp.StatusCode, body)
	}
}

func TestPostScanReturnsReport(t *testing.T) {
	srv := newTestServer(t)
	status, body := post(t, srv, `{"url":"https://example.com"}`)
	if status != http.StatusOK {
		t.Fatalf("POST /v1/scans: status %d, body %s", status, body)
	}
	for _, want := range []string{`"targetUrl":"https://example.com"`, `"scanStatus":"SCAN_STATUS_OK"`} {
		if !strings.Contains(body, want) {
			t.Errorf("response lacks %s:\n%s", want, body)
		}
	}
}

func TestPostScanRejectsBadURL(t *testing.T) {
	srv := newTestServer(t)
	if status, body := post(t, srv, `{"url":"ftp://example.com"}`); status != http.StatusBadRequest {
		t.Fatalf("POST bad URL: status %d, want 400, body %s", status, body)
	}
}

// countingService counts the Scan calls that reach the service.
type countingService struct {
	*service.Stub
	calls int
}

func (c *countingService) Scan(ctx context.Context, req *touchstonev1.ScanRequest) (*touchstonev1.ScanReport, error) {
	c.calls++
	return c.Stub.Scan(ctx, req)
}

func TestPostScanRejectsOversizedBody(t *testing.T) {
	svc := &countingService{Stub: &service.Stub{Now: func() time.Time { return time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC) }}}
	srv := newServerFor(t, svc)
	big := `{"url":"https://example.com","sbom_document":"` + strings.Repeat("A", maxRequestBytes) + `"}`
	// The gateway turns the body-read error from MaxBytesHandler into InvalidArgument, which is 400.
	if status, body := post(t, srv, big); status != http.StatusBadRequest {
		t.Errorf("oversized POST = %d, want 400, body %s", status, body)
	}
	if svc.calls != 0 {
		t.Errorf("service was called %d times for an oversized body, want 0", svc.calls)
	}
}
