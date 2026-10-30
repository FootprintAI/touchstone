package vuln

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const nginxCPE = "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*"

// recorded serves one file under testdata for path, records each request,
// and answers anything else with 404 and a test failure.
func recorded(t *testing.T, path, file string) (*httptest.Server, *[]*http.Request) {
	t.Helper()
	var mu sync.Mutex
	var reqs []*http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		reqs = append(reqs, r)
		mu.Unlock()
		if r.Method != http.MethodGet || r.URL.Path != path {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		b, err := os.ReadFile(filepath.Join("testdata", file))
		if err != nil {
			t.Errorf("read fixture: %v", err)
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b)
	}))
	t.Cleanup(srv.Close)
	return srv, &reqs
}

func failing(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestNVDLookupByCPE(t *testing.T) {
	srv, reqs := recorded(t, "/rest/json/cves/2.0", "nvd/cves-nginx-1.18.0.json")
	n := &NVD{BaseURL: srv.URL, Client: srv.Client()}
	got, err := n.Lookup(context.Background(), []Query{{CPE: nginxCPE}})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(got) != 1 || got[0].ID != "CVE-2021-23017" {
		t.Fatalf("Lookup = %+v, want CVE-2021-23017", got)
	}
	if !strings.HasPrefix(got[0].Summary, "A security issue in nginx resolver") {
		t.Errorf("summary = %q, want the English description", got[0].Summary)
	}
	if got[0].CVSSBase == nil || *got[0].CVSSBase != 7.7 {
		t.Errorf("cvss = %v, want the v3.1 primary score 7.7", got[0].CVSSBase)
	}
	if len(*reqs) != 1 {
		t.Fatalf("requests = %d, want 1", len(*reqs))
	}
	r := (*reqs)[0]
	if r.URL.Query().Get("cpeName") != nginxCPE {
		t.Errorf("cpeName = %q, want %q", r.URL.Query().Get("cpeName"), nginxCPE)
	}
	if r.Header.Get("apiKey") != "" {
		t.Errorf("apiKey header sent without a key")
	}
}

func TestNVDSendsAPIKey(t *testing.T) {
	srv, reqs := recorded(t, "/rest/json/cves/2.0", "nvd/cves-nginx-1.18.0.json")
	n := &NVD{BaseURL: srv.URL, APIKey: "k", Client: srv.Client()}
	if _, err := n.Lookup(context.Background(), []Query{{CPE: nginxCPE}}); err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got := (*reqs)[0].Header.Get("apiKey"); got != "k" {
		t.Errorf("apiKey header = %q, want k", got)
	}
}

func TestNVDPerScanLimit(t *testing.T) {
	if got := NewNVD("").PerScanLimit(); got != UnauthenticatedNVDLimit {
		t.Errorf("without a key: limit = %d, want %d", got, UnauthenticatedNVDLimit)
	}
	if got := NewNVD("k").PerScanLimit(); got != 0 {
		t.Errorf("with a key: limit = %d, want 0 (no cap)", got)
	}
}

func TestNVDIgnoresPurlQueries(t *testing.T) {
	srv, reqs := recorded(t, "/rest/json/cves/2.0", "nvd/cves-nginx-1.18.0.json")
	n := &NVD{BaseURL: srv.URL, Client: srv.Client()}
	got, err := n.Lookup(context.Background(), []Query{{Purl: "pkg:npm/jquery@1.12.4", CPE: "cpe:2.3:a:jquery:jquery:1.12.4:*:*:*:*:*:*:*"}})
	if err != nil || len(got) != 0 || len(*reqs) != 0 {
		t.Fatalf("Lookup = %v, %v with %d requests; want nothing asked for a purl query", got, err, len(*reqs))
	}
}

func TestNVDErrors(t *testing.T) {
	for name, body := range map[string]string{
		"no totalResults":   `{"vulnerabilities":[]}`,
		"truncated results": `{"totalResults":3,"vulnerabilities":[{"cve":{"id":"CVE-2021-23017"}}]}`,
		"missing id":        `{"totalResults":1,"vulnerabilities":[{"cve":{}}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(body))
			}))
			t.Cleanup(srv.Close)
			n := &NVD{BaseURL: srv.URL, Client: srv.Client()}
			if got, err := n.Lookup(context.Background(), []Query{{CPE: nginxCPE}}); err == nil || got != nil {
				t.Fatalf("Lookup = %v, %v; want an error and no findings", got, err)
			}
		})
	}
	t.Run("non-200", func(t *testing.T) {
		n := &NVD{BaseURL: failing(t).URL, Client: http.DefaultClient}
		if _, err := n.Lookup(context.Background(), []Query{{CPE: nginxCPE}}); err == nil {
			t.Fatal("Lookup: want an error for HTTP 503")
		}
	})
}

func TestKEVFlagsListedCVEs(t *testing.T) {
	srv, _ := recorded(t, "/kev.json", "kev/known_exploited_vulnerabilities.json")
	k := &KEV{URL: srv.URL + "/kev.json", Client: srv.Client()}
	got, err := k.Enrich(context.Background(), []string{"CVE-2020-11022", "CVE-2019-11358"})
	if err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if !got["CVE-2020-11022"].KEV {
		t.Errorf("CVE-2020-11022 not flagged: %v", got)
	}
	if _, ok := got["CVE-2019-11358"]; ok {
		t.Errorf("CVE-2019-11358 is not in the catalog but was returned: %v", got)
	}
}

func TestKEVCachesForTTL(t *testing.T) {
	srv, reqs := recorded(t, "/kev.json", "kev/known_exploited_vulnerabilities.json")
	now := time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
	k := &KEV{URL: srv.URL + "/kev.json", Client: srv.Client(), Now: func() time.Time { return now }}
	ctx := context.Background()
	for _, step := range []struct {
		advance time.Duration
		fetches int
	}{
		{0, 1},
		{KEVTTL - time.Minute, 1}, // still fresh: served from memory
		{2 * time.Minute, 2},      // past the TTL: fetched again
	} {
		now = now.Add(step.advance)
		if _, err := k.Enrich(ctx, []string{"CVE-2020-11022"}); err != nil {
			t.Fatalf("Enrich: %v", err)
		}
		if len(*reqs) != step.fetches {
			t.Errorf("after +%v: fetches = %d, want %d", step.advance, len(*reqs), step.fetches)
		}
	}
}

func TestKEVErrors(t *testing.T) {
	k := &KEV{URL: failing(t).URL, Client: http.DefaultClient}
	if _, err := k.Enrich(context.Background(), []string{"CVE-2020-11022"}); err == nil {
		t.Error("Enrich: want an error for HTTP 503")
	}
	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"vulnerabilities":[]}`))
	}))
	t.Cleanup(empty.Close)
	k = &KEV{URL: empty.URL, Client: empty.Client()}
	if _, err := k.Enrich(context.Background(), []string{"CVE-2020-11022"}); err == nil {
		t.Error("Enrich: want an error for an empty catalog, not \"nothing is exploited\"")
	}
}

func TestEPSSScores(t *testing.T) {
	srv, reqs := recorded(t, "/data/v1/epss", "epss/epss.json")
	e := &EPSS{BaseURL: srv.URL, Client: srv.Client()}
	got, err := e.Enrich(context.Background(), []string{"CVE-2020-11022", "GHSA-xxxx-xxxx-xxxx"})
	if err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if s := got["CVE-2020-11022"].EPSS; s == nil || *s != 0.00281 {
		t.Errorf("CVE-2020-11022 epss = %v, want 0.00281", s)
	}
	if len(*reqs) != 1 || (*reqs)[0].URL.Query().Get("cve") != "CVE-2020-11022" {
		t.Errorf("requests = %v, want one asking only for the CVE id", *reqs)
	}
}

func TestEPSSSkipsRequestWithoutCVEs(t *testing.T) {
	e := &EPSS{BaseURL: "http://unused.invalid", Client: http.DefaultClient}
	got, err := e.Enrich(context.Background(), []string{"GHSA-xxxx-xxxx-xxxx"})
	if err != nil || len(got) != 0 {
		t.Fatalf("Enrich = %v, %v; want nothing and no request", got, err)
	}
}

func TestEPSSErrors(t *testing.T) {
	e := &EPSS{BaseURL: failing(t).URL, Client: http.DefaultClient}
	if _, err := e.Enrich(context.Background(), []string{"CVE-2020-11022"}); err == nil {
		t.Error("Enrich: want an error for HTTP 503")
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":[{"cve":"CVE-2020-11022","epss":"high"}]}`))
	}))
	t.Cleanup(bad.Close)
	e = &EPSS{BaseURL: bad.URL, Client: bad.Client()}
	if _, err := e.Enrich(context.Background(), []string{"CVE-2020-11022"}); err == nil {
		t.Error("Enrich: want an error for a non-numeric score")
	}
}
