package vuln

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func kevFor(srv *httptest.Server, now func() time.Time) *KEV {
	return &KEV{URL: srv.URL + "/kev.json", Client: srv.Client(), Now: now}
}

func TestKEVFlagsListedCVEsOnly(t *testing.T) {
	srv, _ := fixtureServer(t, "kev/known_exploited_vulnerabilities.json")
	got, err := kevFor(srv, nil).Enrich(context.Background(), []string{"CVE-2020-11022", "CVE-2019-11358", "GHSA-gxr4-xjj5-5px2"})
	if err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if len(got) != 1 || !got["CVE-2020-11022"].KEV {
		t.Errorf("Enrich = %v, want only CVE-2020-11022 flagged KEV", got)
	}
}

func TestKEVWithNoCVEIDsMakesNoRequest(t *testing.T) {
	srv, log := fixtureServer(t, "kev/known_exploited_vulnerabilities.json")
	got, err := kevFor(srv, nil).Enrich(context.Background(), []string{"GHSA-gxr4-xjj5-5px2"})
	if err != nil || len(got) != 0 {
		t.Fatalf("Enrich = %v, %v; want nothing and no error", got, err)
	}
	if log.count() != 0 {
		t.Errorf("fetched the catalog for non-CVE ids: %d requests", log.count())
	}
}

func TestKEVCatalogIsCachedForTTL(t *testing.T) {
	srv, log := fixtureServer(t, "kev/known_exploited_vulnerabilities.json")
	clock := time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC)
	k := kevFor(srv, func() time.Time { return clock })
	ids := []string{"CVE-2020-11022"}

	for i := 0; i < 2; i++ {
		if _, err := k.Enrich(context.Background(), ids); err != nil {
			t.Fatalf("Enrich: %v", err)
		}
	}
	if log.count() != 1 {
		t.Fatalf("fetches within the TTL = %d, want 1", log.count())
	}

	clock = clock.Add(KEVTTL - time.Minute)
	if _, err := k.Enrich(context.Background(), ids); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if log.count() != 1 {
		t.Fatalf("fetches just inside the TTL = %d, want 1", log.count())
	}

	clock = clock.Add(2 * time.Minute)
	if _, err := k.Enrich(context.Background(), ids); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if log.count() != 2 {
		t.Fatalf("fetches after the TTL = %d, want 2", log.count())
	}
}

func TestKEVFeedErrorIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)
	got, err := kevFor(srv, nil).Enrich(context.Background(), []string{"CVE-2020-11022"})
	if err == nil || got != nil {
		t.Fatalf("Enrich = %v, %v; want an error and no enrichments, never 'not listed'", got, err)
	}
}

func TestKEVEmptyCatalogIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"catalogVersion": "x", "vulnerabilities": []}`))
	}))
	t.Cleanup(srv.Close)
	if _, err := kevFor(srv, nil).Enrich(context.Background(), []string{"CVE-2020-11022"}); err == nil {
		t.Fatal("Enrich: want an error for a catalog with no entries")
	}
}
