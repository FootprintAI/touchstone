package vuln

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// recordedOSV serves the recorded responses under testdata/osv: the
// querybatch reply for POST /v1/querybatch and vulns/<id>.json for
// GET /v1/vulns/<id>. Any other request is a test failure.
func recordedOSV(t *testing.T) (*httptest.Server, *[]string) {
	t.Helper()
	var mu sync.Mutex
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls = append(calls, r.Method+" "+r.URL.Path)
		mu.Unlock()
		var file string
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/querybatch":
			file = "querybatch-jquery-1.12.4.json"
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/vulns/"):
			file = filepath.Join("vulns", strings.TrimPrefix(r.URL.Path, "/v1/vulns/")+".json")
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		b, err := os.ReadFile(filepath.Join("testdata", "osv", file))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b)
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func osvFor(srv *httptest.Server) *OSV {
	return &OSV{BaseURL: srv.URL, Client: srv.Client()}
}

func TestOSVLookupByPurl(t *testing.T) {
	srv, calls := recordedOSV(t)
	got, err := osvFor(srv).Lookup(context.Background(), []Query{{Purl: "pkg:npm/jquery@1.12.4"}})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("Lookup: got %d findings, want 2: %+v", len(got), got)
	}
	// The CVE alias is the id; the OSV id moves to aliases.
	if got[0].ID != "CVE-2019-11358" || got[1].ID != "CVE-2020-11022" {
		t.Errorf("ids = %q, %q; want CVE ids", got[0].ID, got[1].ID)
	}
	if got[1].Summary != "Potential XSS vulnerability in jQuery.htmlPrefilter" {
		t.Errorf("summary = %q", got[1].Summary)
	}
	if !contains(got[1].Aliases, "GHSA-gxr4-xjj5-5px2") {
		t.Errorf("aliases = %v, want the GHSA id kept", got[1].Aliases)
	}
	want := []string{
		"POST /v1/querybatch",
		"GET /v1/vulns/GHSA-6c3j-c64m-qhgq",
		"GET /v1/vulns/GHSA-gxr4-xjj5-5px2",
	}
	if strings.Join(*calls, "|") != strings.Join(want, "|") {
		t.Errorf("calls = %v, want %v", *calls, want)
	}
}

func TestOSVIgnoresCPEOnlyQueries(t *testing.T) {
	srv, calls := recordedOSV(t)
	got, err := osvFor(srv).Lookup(context.Background(), []Query{{CPE: "cpe:2.3:a:jquery:jquery:1.12.4:*:*:*:*:*:*:*"}})
	if err != nil || len(got) != 0 {
		t.Fatalf("Lookup = %v, %v; want no findings and no error", got, err)
	}
	if len(*calls) != 0 {
		t.Errorf("made requests for CPE-only query: %v", *calls)
	}
}

func TestOSVNonOKStatusIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)
	got, err := osvFor(srv).Lookup(context.Background(), []Query{{Purl: "pkg:npm/jquery@1.12.4"}})
	if err == nil || got != nil {
		t.Fatalf("Lookup = %v, %v; want an error and no findings", got, err)
	}
}

func TestOSVResultCountMismatchIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"results": []any{}})
	}))
	t.Cleanup(srv.Close)
	_, err := osvFor(srv).Lookup(context.Background(), []Query{{Purl: "pkg:npm/jquery@1.12.4"}})
	if err == nil {
		t.Fatal("Lookup: want an error when querybatch returns fewer results than queries")
	}
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
