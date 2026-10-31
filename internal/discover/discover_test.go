package discover

import (
	"context"
	"net/url"
	"reflect"
	"testing"

	"github.com/FootprintAI/touchstone/internal/fetch"
	"github.com/FootprintAI/touchstone/internal/pipeline"
)

func TestParseSecurityTxt(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want SecurityTxt
	}{
		{
			name: "multiple CSAF fields, comments, CRLF",
			in: "# Our security contacts\r\n" +
				"Contact: mailto:security@vendor.example\r\n" +
				"Expires: 2027-01-01T00:00:00Z\r\n" +
				"\r\n" +
				"CSAF: https://vendor.example/.well-known/csaf/provider-metadata.json\r\n" +
				"csaf: https://csaf.vendor.example/provider-metadata.json\r\n" +
				"Policy: https://vendor.example/policy\r\n",
			want: SecurityTxt{
				Contact: []string{"mailto:security@vendor.example"},
				Expires: "2027-01-01T00:00:00Z",
				CSAF: []string{
					"https://vendor.example/.well-known/csaf/provider-metadata.json",
					"https://csaf.vendor.example/provider-metadata.json",
				},
			},
		},
		{
			name: "OpenPGP cleartext signature",
			in: "-----BEGIN PGP SIGNED MESSAGE-----\n" +
				"Hash: SHA256\n\n" +
				"Contact: https://vendor.example/report\n" +
				"- CSAF: https://vendor.example/pm.json\n" +
				"-----BEGIN PGP SIGNATURE-----\n" +
				"CSAF: https://not-a-field.example/\n" +
				"-----END PGP SIGNATURE-----\n",
			want: SecurityTxt{
				Contact: []string{"https://vendor.example/report"},
				CSAF:    []string{"https://vendor.example/pm.json"},
			},
		},
		{
			name: "not a security.txt",
			in:   "<html><body>Not found</body></html>",
			want: SecurityTxt{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParseSecurityTxt([]byte(tt.in)); !reflect.DeepEqual(*got, tt.want) {
				t.Errorf("ParseSecurityTxt =\n%+v\nwant\n%+v", *got, tt.want)
			}
		})
	}
}

func TestRepoLinks(t *testing.T) {
	page, _ := url.Parse("https://vendor.example/about")
	body := `<html><body>
<a href="https://github.com/vendor/app">Source</a>
<a href="https://github.com/Vendor/App/tree/main/src">same repo, other page</a>
<a href="https://gitlab.com/group/sub/project/-/releases">GitLab</a>
<a href="git+https://github.com/vendor/scheme">not http</a>
<a href="https://github.com/vendor/lib.git">clone URL</a>
<a href="https://github.com/vendor/app/actions"><img src="https://github.com/vendor/ci/actions/workflows/ci.yml/badge.svg"></a>
<a href="https://github.com/vendor/badged"><img src="https://img.shields.io/github/stars/vendor/badged"></a>
<a href="https://github.com/vendor/ci/actions/workflows/ci.yml/badge.svg">badge</a>
<a href="https://github.com/login?return_to=https%3A%2F%2Fvendor.example">Sign in</a>
<a href="https://github.com/sponsors/vendor">Sponsor</a>
<a href="https://twitter.com/intent/tweet?url=https://github.com/vendor/shared">Share</a>
<a href="https://github.com/vendor">profile, not a repo</a>
<a href="https://github.com/vendor/logo"><img src="/img/github-mark.png" alt="GitHub"></a>
</body></html>`
	got, err := RepoLinks(page, []byte(body))
	if err != nil {
		t.Fatalf("RepoLinks: %v", err)
	}
	want := []string{
		"https://github.com/vendor/app",
		"https://gitlab.com/group/sub/project",
		"https://github.com/vendor/lib",
		"https://github.com/vendor/logo",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("RepoLinks =\n%q\nwant\n%q", got, want)
	}
}

const (
	target     = "https://vendor.example/"
	wellKnown  = "https://vendor.example/.well-known/csaf/provider-metadata.json"
	declaredPM = "https://csaf.vendor.example/provider-metadata.json"
	feedURL    = "https://csaf.vendor.example/white/feed.json"
	vexURL     = "https://csaf.vendor.example/white/2026/vex-1.json"
	advisory   = "https://csaf.vendor.example/white/2025/adv-1.json"
)

const providerMetadataJSON = `{
  "canonical_url": "` + declaredPM + `",
  "metadata_version": "2.0",
  "role": "csaf_provider",
  "distributions": [
    {"rolie": {"feeds": [
      {"tlp_label": "WHITE", "url": "` + feedURL + `"},
      {"tlp_label": "AMBER", "url": "https://csaf.vendor.example/amber/feed.json"}
    ]}},
    {"directory_url": "https://csaf.vendor.example/white/"}
  ]
}`

const feedJSON = `{"feed": {"id": "vendor-white", "entry": [
  {"id": "adv-1", "updated": "2025-03-01T00:00:00Z", "content": {"type": "application/json", "src": "` + advisory + `"}},
  {"id": "vex-1", "updated": "2026-09-01T00:00:00Z", "link": [{"rel": "self", "href": "` + vexURL + `"}]}
]}}`

const vexJSON = `{
  "document": {"category": "csaf_vex", "csaf_version": "2.0"},
  "product_tree": {"full_product_names": [
    {"product_id": "P1", "name": "jquery 3.7.1", "product_identification_helper": {"purl": "pkg:npm/jquery@3.7.1"}}
  ]}
}`

const advisoryJSON = `{
  "document": {"category": "csaf_security_advisory", "csaf_version": "2.0"},
  "product_tree": {"full_product_names": [{"product_id": "P9", "name": "Other product"}]}
}`

func ok(u, body string) *fetch.Response {
	return &fetch.Response{URL: u, StatusCode: 200, Body: []byte(body)}
}

func notFound(u string) *fetch.Response {
	return &fetch.Response{URL: u, StatusCode: 404}
}

// vendorFake is a vendor publishing security.txt with two CSAF fields (one
// the well-known URL), provider metadata with one public ROLIE feed, and a
// TEA document that names an endpoint discovery must not query.
func vendorFake() *fetch.Fake {
	f := fetch.NewFake()
	f.SetResponse(target+".well-known/security.txt", ok(target+".well-known/security.txt",
		"Contact: mailto:psirt@vendor.example\nCSAF: "+wellKnown+"\nCSAF: "+declaredPM+"\n"))
	f.SetResponse(wellKnown, ok(wellKnown, providerMetadataJSON))
	f.SetResponse(target+".well-known/tea", ok(target+".well-known/tea",
		`{"endpoints": [{"url": "https://tea.vendor.example/v1"}]}`))
	f.SetResponse(declaredPM, ok(declaredPM, providerMetadataJSON))
	f.SetResponse(feedURL, ok(feedURL, feedJSON))
	f.SetResponse(vexURL, ok(vexURL, vexJSON))
	f.SetResponse(advisory, ok(advisory, advisoryJSON))
	return f
}

func TestDiscoverFollowsSecurityTxtToCSAFVEX(t *testing.T) {
	f := vendorFake()
	page := ok(target, `<a href="https://github.com/vendor/app">code</a>`)
	res, err := Discover(context.Background(), f, target, page)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	wantCalls := []fetch.Call{
		{URL: target + ".well-known/security.txt", Reason: fetch.ReasonDiscoveryPath},
		{URL: wellKnown, Reason: fetch.ReasonDiscoveryPath},
		{URL: target + ".well-known/tea", Reason: fetch.ReasonDiscoveryPath},
		{URL: declaredPM, Reason: fetch.ReasonDeclared},
		{URL: feedURL, Reason: fetch.ReasonDeclared},
		{URL: vexURL, Reason: fetch.ReasonDeclared},
		{URL: advisory, Reason: fetch.ReasonDeclared},
	}
	if !reflect.DeepEqual(f.Calls, wantCalls) {
		t.Errorf("calls =\n%v\nwant\n%v", f.Calls, wantCalls)
	}

	if res.SecurityTxt == nil || len(res.SecurityTxt.CSAF) != 2 {
		t.Errorf("SecurityTxt = %+v, want two CSAF fields", res.SecurityTxt)
	}
	if want := []string{declaredPM, wellKnown}; !reflect.DeepEqual(res.ProviderMetadata, want) {
		t.Errorf("ProviderMetadata = %q, want %q", res.ProviderMetadata, want)
	}
	if want := []string{vexURL}; !reflect.DeepEqual(res.VEXDocuments, want) {
		t.Errorf("VEXDocuments = %q, want only the csaf_vex document %q", res.VEXDocuments, want)
	}
	if !res.TEA {
		t.Error("TEA = false, want the /.well-known/tea document recorded")
	}
	if want := []string{"https://github.com/vendor/app"}; !reflect.DeepEqual(res.RepoLinks, want) {
		t.Errorf("RepoLinks = %q, want %q", res.RepoLinks, want)
	}
	wantComps := []pipeline.Component{{
		Name: "jquery", Version: "3.7.1", Purl: "pkg:npm/jquery@3.7.1", Confidence: "HIGH",
		Evidence: []pipeline.Evidence{{Kind: "VEX", Location: vexURL, Detail: "CSAF VEX product"}},
	}}
	if !reflect.DeepEqual(res.Components, wantComps) {
		t.Errorf("Components =\n%+v\nwant\n%+v", res.Components, wantComps)
	}
}

func TestDiscoverFallsBackToRootSecurityTxt(t *testing.T) {
	f := fetch.NewFake()
	f.SetResponse(target+".well-known/security.txt", notFound(target+".well-known/security.txt"))
	f.SetResponse(target+"security.txt", ok(target+"security.txt", "Contact: mailto:a@vendor.example\n"))
	f.SetResponse(wellKnown, notFound(wellKnown))
	f.SetResponse(target+".well-known/tea", notFound(target+".well-known/tea"))

	res, err := Discover(context.Background(), f, target, nil)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if res.SecurityTxt == nil || len(res.SecurityTxt.Contact) != 1 {
		t.Errorf("SecurityTxt = %+v, want the root security.txt", res.SecurityTxt)
	}
	if res.TEA || len(res.ProviderMetadata) != 0 || len(res.Components) != 0 {
		t.Errorf("result = %+v, want nothing beyond security.txt", res)
	}
	if len(f.Calls) != 4 {
		t.Errorf("calls = %v, want the four discovery paths only", f.Calls)
	}
	for _, c := range f.Calls {
		if c.Reason != fetch.ReasonDiscoveryPath {
			t.Errorf("call %v, want only DISCOVERY_PATH requests", c)
		}
	}
}

func TestDiscoverReportsUnreadableDocuments(t *testing.T) {
	f := fetch.NewFake()
	f.SetResponse(wellKnown, ok(wellKnown, "<html>soft 404</html>"))
	res, err := Discover(context.Background(), f, target, nil)
	if err == nil {
		t.Fatal("Discover: want an error for provider metadata that is not JSON")
	}
	if res == nil || len(res.ProviderMetadata) != 0 {
		t.Errorf("result = %+v, want a result without provider metadata", res)
	}
}

func TestDiscoverCapsDocuments(t *testing.T) {
	f := fetch.NewFake()
	f.SetResponse(wellKnown, ok(wellKnown, providerMetadataJSON))
	feed := `{"feed": {"entry": [`
	for i := range MaxDocuments + 3 {
		if i > 0 {
			feed += ","
		}
		feed += `{"content": {"src": "https://csaf.vendor.example/white/d` + string(rune('a'+i)) + `.json"}}`
	}
	feed += `]}}`
	f.SetResponse(feedURL, ok(feedURL, feed))

	_, _ = Discover(context.Background(), f, target, nil)
	docs := 0
	for _, c := range f.Calls {
		if c.Reason == fetch.ReasonDeclared && c.URL != feedURL {
			docs++
		}
	}
	if docs != MaxDocuments {
		t.Errorf("fetched %d CSAF documents, want the cap of %d", docs, MaxDocuments)
	}
}
