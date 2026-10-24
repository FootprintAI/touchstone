package fingerprint

import (
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

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
