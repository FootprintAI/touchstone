package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	touchstonev1 "github.com/FootprintAI/touchstone/gen/go/touchstone/v1"
	"github.com/FootprintAI/touchstone/internal/fetch"
	"github.com/FootprintAI/touchstone/internal/vuln"
)

const (
	cycloneDXSample = `{"bomFormat":"CycloneDX","components":[{"name":"lodash","version":"4.17.21","purl":"pkg:npm/lodash@4.17.21"}]}`
	csafVEXSample   = `{"document":{"category":"csaf_vex"},"product_tree":{"full_product_names":[{"name":"Widget","product_id":"W","product_identification_helper":{"purl":"pkg:npm/widget@2.0.0"}}]}}`
)

// csafSite serves a page plus security.txt → provider metadata → ROLIE
// feed → one VEX document, and a reviewer-supplied SBOM at /sbom.json.
func csafSite(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/{$}", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><body><a href="https://github.com/vendor/app">src</a></body></html>`))
	})
	mux.HandleFunc("/.well-known/security.txt", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("Contact: mailto:sec@vendor.example\r\nCSAF: http://" + r.Host + "/.well-known/csaf/provider-metadata.json\r\n"))
	})
	mux.HandleFunc("/.well-known/csaf/provider-metadata.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"distributions":[{"rolie":{"feeds":[{"url":"/csaf/feed.json"}]}}]}`))
	})
	mux.HandleFunc("/csaf/feed.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"feed":{"entry":[{"content":{"src":"/csaf/vex.json"}}]}}`))
	})
	mux.HandleFunc("/csaf/vex.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(csafVEXSample))
	})
	mux.HandleFunc("/sbom.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(cycloneDXSample))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func scannerWithNoVulns() *Scanner {
	return &Scanner{
		Fetch: fetch.Options{AllowPrivate: true, Version: ToolVersion},
		Vulns: &vuln.FakeSource{SourceName: "fake"},
	}
}

func findComponent(rep *touchstonev1.ScanReport, name string) *touchstonev1.Component {
	for _, c := range rep.GetComponents() {
		if c.GetName() == name {
			return c
		}
	}
	return nil
}

func TestScannerFollowsCSAFToVEX(t *testing.T) {
	site := csafSite(t)
	rep, err := scannerWithNoVulns().Scan(context.Background(), &touchstonev1.ScanRequest{Url: site.URL + "/"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	found := map[string]string{}
	for _, c := range rep.GetChecked() {
		if c.GetResult() == touchstonev1.CheckedLocation_RESULT_FOUND {
			found[c.GetUrl()] = c.GetReason()
		}
	}
	for url, reason := range map[string]string{
		site.URL + "/.well-known/security.txt":                 "DISCOVERY_PATH",
		site.URL + "/.well-known/csaf/provider-metadata.json": "DECLARED",
		site.URL + "/csaf/vex.json":                            "DECLARED",
	} {
		if found[url] != reason {
			t.Errorf("checked lacks FOUND %s %s; found = %v", reason, url, found)
		}
	}

	w := findComponent(rep, "widget")
	if w == nil {
		t.Fatalf("no widget component from the VEX document in %v", rep.GetComponents())
	}
	if w.GetConfidence() != touchstonev1.Confidence_CONFIDENCE_HIGH ||
		w.GetEvidence()[0].GetKind() != touchstonev1.EvidenceKind_EVIDENCE_KIND_VEX ||
		w.GetEvidence()[0].GetLocation() != site.URL+"/csaf/vex.json" {
		t.Errorf("widget = %v, want High confidence VEX evidence from the VEX URL", w)
	}
}

func TestScannerSuppliedSBOMIsHighConfidence(t *testing.T) {
	site := csafSite(t)
	for name, req := range map[string]*touchstonev1.ScanRequest{
		"document": {Url: site.URL + "/", SbomDocument: []byte(cycloneDXSample)},
		"url":      {Url: site.URL + "/", SbomUrl: site.URL + "/sbom.json"},
	} {
		t.Run(name, func(t *testing.T) {
			rep, err := scannerWithNoVulns().Scan(context.Background(), req)
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			c := findComponent(rep, "lodash")
			if c == nil {
				t.Fatalf("no lodash component in %v", rep.GetComponents())
			}
			if c.GetConfidence() != touchstonev1.Confidence_CONFIDENCE_HIGH || c.GetVersion() != "4.17.21" ||
				c.GetEvidence()[0].GetKind() != touchstonev1.EvidenceKind_EVIDENCE_KIND_SBOM_SUPPLIED {
				t.Errorf("lodash = %v, want High confidence with SBOM_SUPPLIED evidence", c)
			}
			var supplied *touchstonev1.SourceStatus
			for _, s := range rep.GetSources() {
				if s.GetSource() == "sbom-supplied" {
					supplied = s
				}
			}
			if supplied == nil || !supplied.GetOk() {
				t.Errorf("sbom-supplied source = %v, want ok", supplied)
			}
		})
	}
}

func TestScannerSuppliedSBOMURLAppearsInChecked(t *testing.T) {
	site := csafSite(t)
	rep, err := scannerWithNoVulns().Scan(context.Background(),
		&touchstonev1.ScanRequest{Url: site.URL + "/", SbomUrl: site.URL + "/sbom.json"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	for _, c := range rep.GetChecked() {
		if c.GetUrl() == site.URL+"/sbom.json" {
			if c.GetReason() != "DECLARED" || c.GetResult() != touchstonev1.CheckedLocation_RESULT_FOUND {
				t.Errorf("sbom_url entry = %v, want DECLARED FOUND", c)
			}
			return
		}
	}
	t.Errorf("sbom_url missing from checked: %v", rep.GetChecked())
}

func TestScannerBadSuppliedSBOM(t *testing.T) {
	site := csafSite(t)
	if _, err := scannerWithNoVulns().Scan(context.Background(),
		&touchstonev1.ScanRequest{Url: site.URL + "/", SbomUrl: "ftp://x.example/sbom.json"}); err == nil {
		t.Error("Scan: want InvalidArgument for a non-http sbom_url")
	}

	rep, err := scannerWithNoVulns().Scan(context.Background(),
		&touchstonev1.ScanRequest{Url: site.URL + "/", SbomDocument: []byte(`{"unknown":true}`)})
	if err != nil {
		t.Fatalf("Scan: an unparseable SBOM is a source error, not an RPC error: %v", err)
	}
	for _, s := range rep.GetSources() {
		if s.GetSource() == "sbom-supplied" && !s.GetOk() && s.GetError() != "" {
			return
		}
	}
	t.Errorf("sources = %v, want sbom-supplied ok=false with an error", rep.GetSources())
}
