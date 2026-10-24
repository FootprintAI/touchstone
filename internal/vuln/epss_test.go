package vuln

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func epssFor(srv *httptest.Server) *EPSS {
	return &EPSS{BaseURL: srv.URL + "/data/v1/epss", Client: srv.Client()}
}

func TestEPSSScoresKnownCVEs(t *testing.T) {
	srv, _ := fixtureServer(t, "epss/epss.json")
	got, err := epssFor(srv).Enrich(context.Background(), []string{"CVE-2020-11022", "CVE-2019-11358", "CVE-2099-0002", "GHSA-gxr4-xjj5-5px2"})
	if err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if e := got["CVE-2020-11022"]; e.EPSS == nil || *e.EPSS != 0.94321 {
		t.Errorf("CVE-2020-11022 EPSS = %v, want 0.94321", e.EPSS)
	}
	if e := got["CVE-2019-11358"]; e.EPSS == nil || *e.EPSS != 0.01234 {
		t.Errorf("CVE-2019-11358 EPSS = %v, want 0.01234", e.EPSS)
	}
	if _, ok := got["CVE-2099-0002"]; ok {
		t.Error("a CVE EPSS does not score got an entry; it must be left absent")
	}
	if _, ok := got["GHSA-gxr4-xjj5-5px2"]; ok {
		t.Error("a non-CVE id got an entry")
	}
}

func TestEPSSSendsOnlyCVEIDs(t *testing.T) {
	srv, log := fixtureServer(t, "epss/epss.json")
	if _, err := epssFor(srv).Enrich(context.Background(), []string{"GHSA-gxr4-xjj5-5px2"}); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if log.count() != 0 {
		t.Errorf("made %d requests for non-CVE ids", log.count())
	}
}

func TestEPSSBatchesLargeLists(t *testing.T) {
	srv, log := fixtureServer(t, "epss/epss.json")
	var cves []string
	for i := 0; i < epssBatch+1; i++ {
		cves = append(cves, fmt.Sprintf("CVE-2099-%04d", i))
	}
	if _, err := epssFor(srv).Enrich(context.Background(), cves); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if log.count() != 2 {
		t.Fatalf("requests = %d for %d ids, want 2 batches", log.count(), len(cves))
	}
	first := strings.Split(log.reqs[0].URL.Query().Get("cve"), ",")
	if len(first) != epssBatch {
		t.Errorf("first batch has %d ids, want %d", len(first), epssBatch)
	}
}

func TestEPSSNonOKStatusIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status": "ERROR", "data": []}`))
	}))
	t.Cleanup(srv.Close)
	got, err := epssFor(srv).Enrich(context.Background(), []string{"CVE-2020-11022"})
	if err == nil || got != nil {
		t.Fatalf("Enrich = %v, %v; want an error and no enrichments", got, err)
	}
}
