package vuln

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const nginxCPE = "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*"

func nvdFor(srv *httptest.Server, apiKey string) *NVD {
	return &NVD{BaseURL: srv.URL, Client: srv.Client(), APIKey: apiKey}
}

func TestNVDLookupByCPE(t *testing.T) {
	srv, log := fixtureServer(t, "nvd/cpe-nginx-1.18.0.json")
	got, err := nvdFor(srv, "").Lookup(context.Background(), []Query{{CPE: nginxCPE}})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("Lookup: got %d findings, want 2 (the rejected CVE is dropped): %+v", len(got), got)
	}
	if got[0].ID != "CVE-2021-23017" || got[0].CVSSBase == nil || *got[0].CVSSBase != 7.7 {
		t.Errorf("first finding = %+v, want CVE-2021-23017 with CVSS 7.7 from the v3.1 primary metric", got[0])
	}
	if got[0].Summary != "fixture: off-by-one in the nginx resolver" {
		t.Errorf("summary = %q, want the English description", got[0].Summary)
	}
	if got[1].ID != "CVE-2019-20372" || got[1].CVSSBase == nil || *got[1].CVSSBase != 5.0 {
		t.Errorf("second finding = %+v, want CVE-2019-20372 with CVSS 5.0 from the v2 metric", got[1])
	}
	if log.count() != 1 {
		t.Fatalf("requests = %d, want one per CPE", log.count())
	}
	r := log.reqs[0]
	if r.URL.Path != "/rest/json/cves/2.0" || r.URL.Query().Get("cpeName") != nginxCPE {
		t.Errorf("request = %s, want the CVE 2.0 path with cpeName=%s", r.URL, nginxCPE)
	}
}

func TestNVDIgnoresQueriesWithoutCPE(t *testing.T) {
	srv, log := fixtureServer(t, "nvd/cpe-nginx-1.18.0.json")
	got, err := nvdFor(srv, "").Lookup(context.Background(), []Query{{Purl: "pkg:npm/jquery@1.12.4"}})
	if err != nil || len(got) != 0 {
		t.Fatalf("Lookup = %v, %v; want no findings and no error", got, err)
	}
	if log.count() != 0 {
		t.Errorf("made %d requests for a purl-only query", log.count())
	}
}

func TestNVDAPIKeyIsSentAsHeaderNotInURL(t *testing.T) {
	srv, log := fixtureServer(t, "nvd/cpe-nginx-1.18.0.json")
	const key = "test-key-not-real"
	if _, err := nvdFor(srv, key).Lookup(context.Background(), []Query{{CPE: nginxCPE}}); err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	r := log.reqs[0]
	if r.Header.Get("apiKey") != key {
		t.Errorf("apiKey header = %q, want the configured key", r.Header.Get("apiKey"))
	}
	if r.URL.RawQuery == "" || strings.Contains(r.URL.RawQuery, key) {
		t.Errorf("query = %q, want the CPE and no key", r.URL.RawQuery)
	}
}

func TestNVDNoKeySendsNoHeader(t *testing.T) {
	srv, log := fixtureServer(t, "nvd/cpe-nginx-1.18.0.json")
	if _, err := nvdFor(srv, "").Lookup(context.Background(), []Query{{CPE: nginxCPE}}); err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if v := log.reqs[0].Header.Values("apiKey"); len(v) != 0 {
		t.Errorf("apiKey header sent without a key: %v", v)
	}
}

func TestNVDNonOKStatusIsError(t *testing.T) {
	// NVD answers 403 when the key is wrong or the rate limit is exceeded.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Forbidden", http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	got, err := nvdFor(srv, "").Lookup(context.Background(), []Query{{CPE: nginxCPE}})
	if err == nil || got != nil {
		t.Fatalf("Lookup = %v, %v; want an error and no findings", got, err)
	}
}

func TestNVDTruncatedPageIsError(t *testing.T) {
	// totalResults above the number returned means a page was cut short,
	// which must not be read as the complete list.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"totalResults": 5, "vulnerabilities": [{"cve": {"id": "CVE-2021-23017", "vulnStatus": "Analyzed"}}]}`))
	}))
	t.Cleanup(srv.Close)
	if _, err := nvdFor(srv, "").Lookup(context.Background(), []Query{{CPE: nginxCPE}}); err == nil {
		t.Fatal("Lookup: want an error when NVD returns fewer results than totalResults")
	}
}

func TestNVDMaxLookups(t *testing.T) {
	if got := NVDMaxLookups(""); got != 5 {
		t.Errorf("without a key = %d, want 5", got)
	}
	if got := NVDMaxLookups("k"); got != 50 {
		t.Errorf("with a key = %d, want 50", got)
	}
}
