package fingerprint

import (
	"crypto/sha1"
	"encoding/hex"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

const (
	reactBundle = "/** @license React v18.2.0\n * react.production.min.js\n */\n(function(){var a=1})();"
	vueBundle   = "/*!\n * Vue.js v2.6.14\n * (c) 2014-2021 Evan You\n */\n(function(g,f){})(this,function(){});"
)

func TestFromContent(t *testing.T) {
	tests := []struct {
		name, body, want, purl string
	}{
		{"react", reactBundle, "react 18.2.0", "pkg:npm/react@18.2.0"},
		{"vue", vueBundle, "vue 2.6.14", "pkg:npm/vue@2.6.14"},
		{"unrelated", "var x = 1;", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := FromContent("https://vendor.example/app.js", []byte(tt.body))
			if err != nil {
				t.Fatalf("FromContent: %v", err)
			}
			if tt.want == "" {
				if len(got) != 0 {
					t.Fatalf("FromContent = %+v, want none", got)
				}
				return
			}
			if len(got) != 1 || got[0].Name+" "+got[0].Version != tt.want || got[0].Purl != tt.purl {
				t.Fatalf("FromContent = %+v, want %s %s", got, tt.want, tt.purl)
			}
			e := got[0].Evidence
			if got[0].Confidence != "LOW" || len(e) != 1 || e[0].Kind != "FINGERPRINT_ASSET" || e[0].Location != "https://vendor.example/app.js" {
				t.Errorf("component = %+v", got[0])
			}
		})
	}
}

// withLibraries swaps the compiled signatures for the test's duration.
func withLibraries(t *testing.T, sigs string) {
	t.Helper()
	libs, err := compile([]byte(sigs))
	if err != nil {
		t.Fatal(err)
	}
	saved := libraries
	libraries = libs
	t.Cleanup(func() { libraries = saved })
}

func TestFromContentHash(t *testing.T) {
	body := []byte("known bundle")
	sum := sha1.Sum(body)
	withLibraries(t, `{"libraries":[{"name":"lib","purl":"pkg:npm/lib@{version}","cpe":"","extractors":{"hashes":{"`+
		hex.EncodeToString(sum[:])+`":"1.2.3"}}}]}`)
	got, err := FromContent("https://vendor.example/lib.js", body)
	if err != nil || len(got) != 1 || got[0].Version != "1.2.3" || got[0].Purl != "pkg:npm/lib@1.2.3" {
		t.Fatalf("FromContent = %+v, %v", got, err)
	}
}

// A pattern with nested quantifiers backtracks exponentially on this input.
// The match must stop at the timeout and come back as an error.
func TestMatchTimeoutReDoS(t *testing.T) {
	withLibraries(t, `{"libraries":[{"name":"evil","purl":"","cpe":"","extractors":{"filecontent":["(a+)+$"]}}]}`)
	start := time.Now()
	got, err := FromContent("https://vendor.example/x.js", []byte(strings.Repeat("a", 64)+"!"))
	if err == nil {
		t.Fatalf("FromContent = %+v, want a timeout error", got)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("match took %v, want it cut off near %v", elapsed, matchTimeout)
	}
}

func TestSignaturesCompile(t *testing.T) {
	libs, err := compile(signatureData)
	if err != nil {
		t.Fatalf("compile embedded signatures: %v", err)
	}
	if len(libs) == 0 {
		t.Fatal("no libraries in embedded signatures")
	}
}

func TestFromURL(t *testing.T) {
	tests := []struct {
		name   string
		url    string
		want   string // version; "" = no component
		purl   string
		detail string
	}{
		{"jquery min", "https://vendor.example/js/jquery-1.12.4.min.js", "1.12.4", "pkg:npm/jquery@1.12.4", "jquery-1.12.4.min.js"},
		{"jquery unminified", "https://vendor.example/jquery-3.7.1.js", "3.7.1", "pkg:npm/jquery@3.7.1", "jquery-3.7.1.js"},
		{"jquery v prefix", "https://cdn.example/jquery.v2.2.4.min.js", "2.2.4", "pkg:npm/jquery@2.2.4", "jquery.v2.2.4.min.js"},
		{"jquery slim", "https://cdn.example/jquery-3.6.0.slim.min.js", "3.6.0", "pkg:npm/jquery@3.6.0", "jquery-3.6.0.slim.min.js"},
		{"query string does not hide it", "https://vendor.example/js/jquery-1.12.4.min.js?v=9", "1.12.4", "pkg:npm/jquery@1.12.4", "jquery-1.12.4.min.js"},
		{"other script", "https://vendor.example/js/app.js", "", "", ""},
		{"jquery-ui is not jquery", "https://vendor.example/jquery-ui-1.12.1.js", "", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := FromURL(tt.url)
			if err != nil {
				t.Fatalf("FromURL: %v", err)
			}
			if tt.want == "" {
				if len(got) != 0 {
					t.Fatalf("FromURL = %+v, want no components", got)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("FromURL = %+v, want one component", got)
			}
			c := got[0]
			if c.Name != "jquery" || c.Version != tt.want || c.Purl != tt.purl {
				t.Errorf("component = name %q version %q purl %q; want jquery %s %s", c.Name, c.Version, c.Purl, tt.want, tt.purl)
			}
			if c.Confidence != "LOW" {
				t.Errorf("confidence = %q, want LOW", c.Confidence)
			}
			if len(c.Evidence) != 1 || c.Evidence[0].Kind != "FINGERPRINT_ASSET" ||
				c.Evidence[0].Location != tt.url || c.Evidence[0].Detail != tt.detail {
				t.Errorf("evidence = %+v, want asset evidence at %s detail %q", c.Evidence, tt.url, tt.detail)
			}
		})
	}
}

func TestScriptURLs(t *testing.T) {
	page, _ := url.Parse("https://vendor.example/app/index.html")
	body := []byte(`<!doctype html><html><head>
		<script src="js/jquery-1.12.4.min.js"></script>
		<script src="/static/app.js?v=2"></script>
		<script src="https://cdn.example/lib/x.js"></script>
		<script src="js/jquery-1.12.4.min.js"></script>
		<script src="javascript:alert(1)"></script>
		<script>var inline = 1;</script>
		</head><body><script type="module" src="./main.mjs"></script></body></html>`)
	got, err := ScriptURLs(page, body)
	if err != nil {
		t.Fatalf("ScriptURLs: %v", err)
	}
	want := []string{
		"https://vendor.example/app/js/jquery-1.12.4.min.js",
		"https://vendor.example/static/app.js?v=2",
		"https://cdn.example/lib/x.js",
		"https://vendor.example/app/main.mjs",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ScriptURLs = %q\nwant %q", got, want)
	}
}

func TestFromHeaders(t *testing.T) {
	page := "https://vendor.example/"
	tests := []struct {
		name   string
		header http.Header
		want   []string // "name version"
	}{
		{"apache", http.Header{"Server": {"Apache/2.4.29 (Ubuntu)"}}, []string{"apache http_server 2.4.29"}},
		{"nginx", http.Header{"Server": {"nginx/1.18.0"}}, []string{"nginx 1.18.0"}},
		{"php", http.Header{"X-Powered-By": {"PHP/7.2.34"}}, []string{"php 7.2.34"}},
		{"unknown banner", http.Header{"Server": {"cloudflare"}}, nil},
		{"no headers", http.Header{}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FromHeaders(page, tt.header)
			var names []string
			for _, c := range got {
				names = append(names, c.Name+" "+c.Version)
				if c.Purl != "" {
					t.Errorf("banner component has purl %q; banners carry CPE only", c.Purl)
				}
				if !contains(c.Caveats, "MAY_BE_BACKPORTED") {
					t.Errorf("caveats = %v, want MAY_BE_BACKPORTED", c.Caveats)
				}
				if len(c.Evidence) != 1 || c.Evidence[0].Kind != "FINGERPRINT_HEADER" || c.Evidence[0].Location != page {
					t.Errorf("evidence = %+v, want header evidence at %s", c.Evidence, page)
				}
				if !strings.HasPrefix(c.CPE, "cpe:2.3:a:") {
					t.Errorf("cpe = %q", c.CPE)
				}
			}
			if !reflect.DeepEqual(names, tt.want) {
				t.Errorf("components = %q, want %q", names, tt.want)
			}
		})
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
