package discover

import (
	"context"
	"net/url"
	"reflect"
	"testing"

	"github.com/FootprintAI/touchstone/internal/fetch"
	"github.com/FootprintAI/touchstone/internal/sbom"
)

func TestParseSecurityTxt(t *testing.T) {
	in := "\ufeff# our policy\r\nContact: mailto:sec@vendor.example\r\n" +
		"csaf: https://vendor.example/.well-known/csaf/provider-metadata.json\r\n" +
		"\r\nCSAF: https://vendor.example/other/provider-metadata.json\r\n" +
		"Expires: 2030-01-01T00:00:00Z\r\nNot a field line\r\nCSAF:\r\n"
	got := ParseSecurityTxt([]byte(in))
	wantCSAF := []string{
		"https://vendor.example/.well-known/csaf/provider-metadata.json",
		"https://vendor.example/other/provider-metadata.json",
	}
	if !reflect.DeepEqual(got.CSAF, wantCSAF) {
		t.Errorf("CSAF = %q, want %q", got.CSAF, wantCSAF)
	}
	if !reflect.DeepEqual(got.Contact, []string{"mailto:sec@vendor.example"}) {
		t.Errorf("Contact = %q", got.Contact)
	}
}

const (
	site     = "https://vendor.example"
	vexDoc   = `{"document":{"category":"csaf_vex"},"product_tree":{"full_product_names":[{"name":"Widget 2.0","product_id":"W","product_identification_helper":{"purl":"pkg:npm/widget@2.0.0"}}]}}`
	advisory = `{"document":{"category":"csaf_security_advisory"}}`
)

func ok(body string) *fetch.Response { return &fetch.Response{StatusCode: 200, Body: []byte(body)} }

func TestRunFollowsSecurityTxtToVEX(t *testing.T) {
	f := fetch.NewFake()
	f.SetResponse(site+"/.well-known/security.txt", ok("Contact: mailto:a@b.example\nCSAF: "+site+"/.well-known/csaf/provider-metadata.json\n"))
	f.SetResponse(site+"/.well-known/csaf/provider-metadata.json",
		ok(`{"distributions":[{"rolie":{"feeds":[{"url":"/csaf/feed.json"}]}}]}`))
	f.SetResponse(site+"/csaf/feed.json",
		ok(`{"feed":{"entry":[{"content":{"src":"/csaf/adv.json"}},{"content":{"src":"/csaf/vex.json"}}]}}`))
	f.SetResponse(site+"/csaf/adv.json", ok(advisory))
	f.SetResponse(site+"/csaf/vex.json", ok(vexDoc))
	f.SetResponse(site+"/.well-known/tea", ok(`{"endpoints":["https://tea.vendor.example/v1"]}`))

	target, _ := url.Parse(site + "/")
	res := Run(context.Background(), f, target, nil)

	if len(res.VEX) != 1 || res.VEX[0].URL != site+"/csaf/vex.json" || res.VEX[0].Doc.Format != sbom.CSAFVEX ||
		res.VEX[0].Doc.Components[0].Purl != "pkg:npm/widget@2.0.0" {
		t.Fatalf("VEX = %+v, want the one VEX document", res.VEX)
	}
	if len(res.Errors) != 0 {
		t.Errorf("Errors = %v", res.Errors)
	}

	want := []fetch.Call{
		{URL: site + "/.well-known/security.txt", Reason: fetch.ReasonDiscoveryPath},
		{URL: site + "/.well-known/csaf/provider-metadata.json", Reason: fetch.ReasonDeclared},
		{URL: site + "/csaf/feed.json", Reason: fetch.ReasonDeclared},
		{URL: site + "/csaf/adv.json", Reason: fetch.ReasonDeclared},
		{URL: site + "/csaf/vex.json", Reason: fetch.ReasonDeclared},
		{URL: site + "/.well-known/tea", Reason: fetch.ReasonDiscoveryPath},
	}
	if !reflect.DeepEqual(f.Calls, want) {
		t.Errorf("calls = %+v\nwant   %+v", f.Calls, want)
	}
}

func TestRunRecordsTEAWithoutQueryingIt(t *testing.T) {
	f := fetch.NewFake()
	f.SetResponse(site+"/.well-known/tea", ok(`{"endpoints":["https://tea.vendor.example/v1"]}`))
	target, _ := url.Parse(site)
	Run(context.Background(), f, target, nil)

	for _, c := range f.Calls {
		if c.URL == "https://tea.vendor.example/v1" {
			t.Errorf("TEA endpoint was queried: %+v", c)
		}
	}
	last := f.Calls[len(f.Calls)-1]
	if last.URL != site+"/.well-known/tea" || last.Reason != fetch.ReasonDiscoveryPath {
		t.Errorf("last call = %+v, want the TEA record as DISCOVERY_PATH", last)
	}
}

func TestRunFallsBackToRootSecurityTxtAndKeepsGoingOnErrors(t *testing.T) {
	f := fetch.NewFake()
	f.SetResponse(site+"/.well-known/security.txt", &fetch.Response{StatusCode: 404})
	f.SetResponse(site+"/security.txt", ok("CSAF: "+site+"/pm.json\n"))
	f.SetResponse(site+"/pm.json", ok(`not json`))
	target, _ := url.Parse(site)
	res := Run(context.Background(), f, target, nil)

	if len(res.VEX) != 0 || len(res.Errors) != 1 {
		t.Errorf("VEX = %+v, Errors = %v; want no VEX and one error for the bad metadata", res.VEX, res.Errors)
	}
	// Provider metadata is probed too (not found) and TEA after it.
	if n := len(f.Calls); n != 5 {
		t.Errorf("calls = %+v, want 5 (2 security.txt, declared metadata, provider path, tea)", f.Calls)
	}
}

func TestRunRejectsNonHTTPCSAFField(t *testing.T) {
	f := fetch.NewFake()
	f.SetResponse(site+"/.well-known/security.txt", ok("CSAF: ftp://vendor.example/pm.json\n"))
	target, _ := url.Parse(site)
	res := Run(context.Background(), f, target, nil)
	if len(res.Errors) != 1 {
		t.Errorf("Errors = %v, want one for the ftp CSAF field", res.Errors)
	}
	for _, c := range f.Calls {
		if c.Reason == fetch.ReasonDeclared {
			t.Errorf("declared fetch for a non-http URL: %+v", c)
		}
	}
}

func TestRepoLinks(t *testing.T) {
	page, _ := url.Parse(site + "/about/")
	body := `<html><head><link rel="source" href="https://gitlab.com/vendor/widget"></head><body>
<a href="https://github.com/vendor/app">source</a>
<a href="https://github.com/vendor/app/issues">issues again</a>
<a href="https://www.github.com/vendor/other.git">other</a>
<a href="https://github.com/vendor/app/actions/workflows/ci.yml"><img src="https://github.com/vendor/app/actions/workflows/ci.yml/badge.svg"></a>
<a href="https://github.com/vendor/badged"><img src="https://img.shields.io/github/stars/vendor/badged"></a>
<a href="https://github.com/sharer/sharer.php?u=x">share</a>
<a href="https://twitter.com/intent/tweet?url=https://github.com/vendor/shared">tweet</a>
<a href="https://github.com/vendor">org only</a>
<a href="https://github.com/features/actions">features</a>
<a href="https://gitlab.com/vendor/widget/-/badges/main/pipeline.svg">pipeline</a>
<a href="/local">local</a>
</body></html>`
	got := RepoLinks(page, []byte(body))
	want := []string{
		"https://gitlab.com/vendor/widget",
		"https://github.com/vendor/app",
		"https://github.com/vendor/other",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("RepoLinks = %q, want %q", got, want)
	}
}
