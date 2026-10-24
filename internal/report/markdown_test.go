package report

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	touchstonev1 "github.com/FootprintAI/touchstone/gen/go/touchstone/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var update = flag.Bool("update", false, "rewrite the golden files under testdata/")

// fixtures are the reports rendered by the golden tests. Each one is
// built in code so the test is the only place that defines it; the
// rendered Markdown lives in testdata/<name>.golden.md.
var fixtures = map[string]func() *touchstonev1.ScanReport{
	// complete: every tier, a VEX-suppressed vulnerability, a version
	// conflict, checked locations and sources. lookup_status is COMPLETE,
	// so counts are rendered.
	"complete": func() *touchstonev1.ScanReport {
		epss, cvss := 0.97, 9.8
		r := base()
		r.Components = []*touchstonev1.Component{
			{
				Name: "lodash", Version: "4.17.20", Purl: "pkg:npm/lodash@4.17.20",
				Confidence: touchstonev1.Confidence_CONFIDENCE_HIGH,
				Evidence: []*touchstonev1.Evidence{{
					Kind: touchstonev1.EvidenceKind_EVIDENCE_KIND_SBOM_PUBLISHED, Location: "https://vendor.example/.well-known/sbom.cdx.json",
				}},
				Vulnerabilities: []*touchstonev1.Vulnerability{
					{Id: "CVE-2021-23337", Aliases: []string{"GHSA-35jh-r3h4-6jhm"}, Summary: "Command injection via template", Kev: true, Epss: &epss, CvssBase: &cvss},
					{Id: "CVE-2020-28500", Summary: "ReDoS in toNumber, trim and trimEnd", VexStatus: touchstonev1.VexStatus_VEX_STATUS_NOT_AFFECTED, VexJustification: "vulnerable_code_not_in_execute_path", Suppressed: true},
				},
			},
			{
				Name: "express", Version: "4.18.2", Purl: "pkg:npm/express@4.18.2",
				Confidence: touchstonev1.Confidence_CONFIDENCE_MEDIUM,
				Evidence: []*touchstonev1.Evidence{{
					Kind: touchstonev1.EvidenceKind_EVIDENCE_KIND_REPO_LOCKFILE, Location: "github.com/vendor/app@v1.2.0:package-lock.json",
				}},
				Caveats: []string{"DEFAULT_BRANCH_NOT_RELEASE"},
			},
			{
				Name: "jquery", Version: "3.4.1", Purl: "pkg:npm/jquery@3.4.1",
				Confidence: touchstonev1.Confidence_CONFIDENCE_LOW,
				Evidence: []*touchstonev1.Evidence{{
					Kind: touchstonev1.EvidenceKind_EVIDENCE_KIND_FINGERPRINT_ASSET, Location: "https://vendor.example/static/jquery-3.4.1.min.js", Detail: "jquery-3.4.1.min.js",
				}},
				Vulnerabilities: []*touchstonev1.Vulnerability{{
					Id: "CVE-2020-11022", Aliases: []string{"GHSA-gxr4-xjj5-5px2"}, Summary: "Potential XSS vulnerability in jQuery.htmlPrefilter",
				}},
			},
			{
				Name: "Apache", Version: "2.4.38", Cpe: "cpe:2.3:a:apache:http_server:2.4.38:*:*:*:*:*:*:*",
				Confidence: touchstonev1.Confidence_CONFIDENCE_LOW,
				Evidence: []*touchstonev1.Evidence{{
					Kind: touchstonev1.EvidenceKind_EVIDENCE_KIND_FINGERPRINT_HEADER, Location: "https://vendor.example/", Detail: "Server: Apache/2.4.38 (Debian)",
				}},
				Caveats: []string{"MAY_BE_BACKPORTED"},
			},
		}
		r.Conflicts = []*touchstonev1.Conflict{{
			ComponentKey: "pkg:npm/jquery", Versions: []string{"3.4.1", "3.7.1"},
			Evidence: []*touchstonev1.Evidence{
				{Kind: touchstonev1.EvidenceKind_EVIDENCE_KIND_FINGERPRINT_ASSET, Location: "https://vendor.example/static/jquery-3.4.1.min.js", Detail: "jquery-3.4.1.min.js"},
				{Kind: touchstonev1.EvidenceKind_EVIDENCE_KIND_SBOM_PUBLISHED, Location: "https://vendor.example/.well-known/sbom.cdx.json", Detail: "pkg:npm/jquery@3.7.1"},
			},
		}}
		r.Checked = []*touchstonev1.CheckedLocation{
			{Url: "https://vendor.example/", Reason: "TARGET", Result: touchstonev1.CheckedLocation_RESULT_FOUND},
			{Url: "https://vendor.example/.well-known/security.txt", Reason: "DISCOVERY_PATH", Result: touchstonev1.CheckedLocation_RESULT_NOT_FOUND},
			{Url: "https://vendor.example/static/jquery-3.4.1.min.js", Reason: "SUBRESOURCE", Result: touchstonev1.CheckedLocation_RESULT_FOUND},
		}
		r.RequestsUsed = 3
		r.Sources = []*touchstonev1.SourceStatus{{Source: "osv", Ok: true}, {Source: "nvd", Ok: true}, {Source: "kev", Ok: true}, {Source: "epss", Ok: true}}
		return r
	},
	// partial: one vulnerability source failed. The report must say
	// "lookup incomplete" and never print a vulnerability count, even
	// for the component whose list is empty.
	"partial": func() *touchstonev1.ScanReport {
		r := base()
		r.LookupStatus = touchstonev1.LookupStatus_LOOKUP_STATUS_PARTIAL
		r.Components = []*touchstonev1.Component{
			{
				Name: "jquery", Version: "3.4.1", Purl: "pkg:npm/jquery@3.4.1",
				Confidence: touchstonev1.Confidence_CONFIDENCE_LOW,
				Evidence:   []*touchstonev1.Evidence{{Kind: touchstonev1.EvidenceKind_EVIDENCE_KIND_FINGERPRINT_ASSET, Location: "https://vendor.example/static/jquery-3.4.1.min.js", Detail: "jquery-3.4.1.min.js"}},
				Vulnerabilities: []*touchstonev1.Vulnerability{{
					Id: "CVE-2020-11022", Summary: "Potential XSS vulnerability in jQuery.htmlPrefilter",
				}},
			},
			{
				Name: "Apache", Version: "2.4.38", Cpe: "cpe:2.3:a:apache:http_server:2.4.38:*:*:*:*:*:*:*",
				Confidence: touchstonev1.Confidence_CONFIDENCE_LOW,
				Evidence:   []*touchstonev1.Evidence{{Kind: touchstonev1.EvidenceKind_EVIDENCE_KIND_FINGERPRINT_HEADER, Location: "https://vendor.example/", Detail: "Server: Apache/2.4.38"}},
				Caveats:    []string{"MAY_BE_BACKPORTED"},
			},
		}
		r.RequestsUsed = 2
		r.Sources = []*touchstonev1.SourceStatus{{Source: "osv", Ok: true}, {Source: "nvd", Ok: false, Error: "Get \"https://services.nvd.nist.gov/rest/json/cves/2.0\": 503 Service Unavailable"}}
		return r
	},
	// failed: no vulnerability source answered and the vulnerability
	// data date is unknown; the metadata lines are still all present.
	"failed": func() *touchstonev1.ScanReport {
		r := base()
		r.LookupStatus = touchstonev1.LookupStatus_LOOKUP_STATUS_FAILED
		r.VulnDataAsOf = nil
		r.Components = []*touchstonev1.Component{{
			Name: "jquery", Version: "3.4.1", Purl: "pkg:npm/jquery@3.4.1",
			Confidence: touchstonev1.Confidence_CONFIDENCE_LOW,
			Evidence:   []*touchstonev1.Evidence{{Kind: touchstonev1.EvidenceKind_EVIDENCE_KIND_FINGERPRINT_ASSET, Location: "https://vendor.example/static/jquery-3.4.1.min.js", Detail: "jquery-3.4.1.min.js"}},
		}}
		r.RequestsUsed = 2
		r.Sources = []*touchstonev1.SourceStatus{{Source: "osv", Ok: false, Error: "dial tcp: i/o timeout"}}
		return r
	},
	// unreachable: the target fetch failed, so there is nothing but
	// metadata, the failed location and the disclaimer.
	"unreachable": func() *touchstonev1.ScanReport {
		r := base()
		r.ScanStatus = touchstonev1.ScanStatus_SCAN_STATUS_TARGET_UNREACHABLE
		r.LookupStatus = touchstonev1.LookupStatus_LOOKUP_STATUS_UNSPECIFIED
		r.VulnDataAsOf = nil
		r.Checked = []*touchstonev1.CheckedLocation{{Url: "https://vendor.example/", Reason: "TARGET", Result: touchstonev1.CheckedLocation_RESULT_ERROR, Error: "dial tcp: lookup vendor.example: no such host"}}
		r.RequestsUsed = 1
		return r
	},
	// injection: Markdown and HTML in every vendor-controlled string.
	"injection": injection,
}

func base() *touchstonev1.ScanReport {
	ts := timestamppb.New(time.Date(2026, 10, 22, 9, 30, 0, 0, time.UTC))
	return &touchstonev1.ScanReport{
		SchemaVersion: "1",
		TargetUrl:     "https://vendor.example/",
		ScanStatus:    touchstonev1.ScanStatus_SCAN_STATUS_OK,
		LookupStatus:  touchstonev1.LookupStatus_LOOKUP_STATUS_COMPLETE,
		StartedAt:     ts,
		CompletedAt:   timestamppb.New(ts.AsTime().Add(12 * time.Second)),
		ToolVersion:   "0.0.0-dev",
		VulnDataAsOf:  timestamppb.New(time.Date(2026, 10, 21, 18, 0, 0, 0, time.UTC)),
		RequestBudget: 50,
		Disclaimer:    Disclaimer,
	}
}

// injectionStrings are the raw vendor strings used by the injection
// fixture. None of them may appear verbatim in the rendered Markdown.
var injectionStrings = []string{
	"<script>alert('xss')</script>",
	"[click me](javascript:alert(1))",
	"**bold** _em_ ~~strike~~",
	"| cell | <img src=x onerror=alert(1)>",
	"`code` \\escape",
	"\n# Injected heading\n\n<iframe src=\"https://evil.example\"></iframe>",
	"&lt;b&gt;entity&lt;/b&gt; &amp; <b>tag</b>",
}

func injection() *touchstonev1.ScanReport {
	r := base()
	r.TargetUrl = "https://vendor.example/?q=" + injectionStrings[0]
	r.ToolVersion = "0.0.0-dev" + injectionStrings[2]
	r.Components = []*touchstonev1.Component{{
		Name:       injectionStrings[0] + injectionStrings[1],
		Version:    injectionStrings[2],
		Purl:       "pkg:npm/" + injectionStrings[3],
		Cpe:        injectionStrings[4],
		Confidence: touchstonev1.Confidence_CONFIDENCE_LOW,
		Evidence: []*touchstonev1.Evidence{{
			Kind:     touchstonev1.EvidenceKind_EVIDENCE_KIND_FINGERPRINT_ASSET,
			Location: "https://vendor.example/" + injectionStrings[1],
			Detail:   injectionStrings[5],
		}},
		Caveats: []string{injectionStrings[6]},
		Vulnerabilities: []*touchstonev1.Vulnerability{
			{Id: injectionStrings[3], Aliases: []string{injectionStrings[2]}, Summary: injectionStrings[0] + injectionStrings[5]},
			{Id: injectionStrings[1], Summary: injectionStrings[4], VexStatus: touchstonev1.VexStatus_VEX_STATUS_NOT_AFFECTED, VexJustification: injectionStrings[5], Suppressed: true},
		},
	}}
	r.Conflicts = []*touchstonev1.Conflict{{ComponentKey: injectionStrings[2], Versions: []string{injectionStrings[3], injectionStrings[4]}}}
	r.Checked = []*touchstonev1.CheckedLocation{{Url: injectionStrings[0], Reason: injectionStrings[3], Result: touchstonev1.CheckedLocation_RESULT_ERROR, Error: injectionStrings[5]}}
	r.Sources = []*touchstonev1.SourceStatus{{Source: injectionStrings[6], Ok: false, Error: injectionStrings[0]}}
	return r
}

func TestMarkdownGolden(t *testing.T) {
	for name, build := range fixtures {
		t.Run(name, func(t *testing.T) {
			got := Markdown(build())
			path := filepath.Join("testdata", name+".golden.md")
			if *update {
				if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read golden (run go test ./internal/report -update): %v", err)
			}
			if got != string(want) {
				t.Errorf("Markdown differs from %s (run go test ./internal/report -update)\ngot:\n%s", path, got)
			}
		})
	}
}

func TestWriteMarkdownReturnsWriteError(t *testing.T) {
	if err := WriteMarkdown(failingWriter{}, base()); err == nil {
		t.Fatal("WriteMarkdown to a failing writer returned nil error")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, os.ErrClosed }

// TestMetadataAndDisclaimerAlwaysPresent checks every fixture, including
// an empty report, for the timestamp, tool version, vulnerability-data
// date and disclaimer lines.
func TestMetadataAndDisclaimerAlwaysPresent(t *testing.T) {
	reports := map[string]*touchstonev1.ScanReport{"empty": {}, "nil": nil}
	for name, build := range fixtures {
		reports[name] = build()
	}
	for name, r := range reports {
		got := Markdown(r)
		for _, want := range []string{
			"- **Started:** ", "- **Completed:** ", "- **Tool version:** ",
			"- **Vulnerability data as of:** ", "- **Vulnerability lookup:** ",
			"> **Disclaimer.** " + Disclaimer + "\n",
		} {
			if !strings.Contains(got, want) {
				t.Errorf("%s: rendering lacks %q:\n%s", name, want, got)
			}
		}
	}
	empty := Markdown(&touchstonev1.ScanReport{})
	for _, want := range []string{"- **Started:** unknown", "- **Tool version:** unknown", "- **Vulnerability data as of:** unknown"} {
		if !strings.Contains(empty, want) {
			t.Errorf("empty report lacks %q:\n%s", want, empty)
		}
	}
}

// countPattern matches any rendered vulnerability count, including the
// zero case that must never look like a clean result.
var countPattern = regexp.MustCompile(`(?i)\b(\d+|no known|zero|none) (vulnerabilit|cve)`)

func TestIncompleteLookupNeverRendersCount(t *testing.T) {
	for _, name := range []string{"partial", "failed", "unreachable"} {
		got := Markdown(fixtures[name]())
		if !strings.Contains(got, "- **Vulnerability lookup:** lookup incomplete") {
			t.Errorf("%s: lookup line does not say \"lookup incomplete\":\n%s", name, got)
		}
		if strings.Contains(got, "**Vulnerability lookup:** complete") {
			t.Errorf("%s: renders lookup as complete", name)
		}
		if m := countPattern.FindString(got); m != "" {
			t.Errorf("%s: renders a vulnerability count %q with an incomplete lookup:\n%s", name, m, got)
		}
		if strings.Contains(got, "- **Vulnerabilities:** no known") || strings.Contains(got, "- **Vulnerabilities:** 1 ") {
			t.Errorf("%s: per-component vulnerability line carries a count:\n%s", name, got)
		}
	}
	for _, name := range []string{"partial", "failed"} {
		if got := Markdown(fixtures[name]()); !strings.Contains(got, "- **Vulnerabilities:** lookup incomplete\n") {
			t.Errorf("%s: component does not say \"lookup incomplete\":\n%s", name, got)
		}
	}
	complete := Markdown(fixtures["complete"]())
	for _, want := range []string{"- **Vulnerability lookup:** complete\n", "- **Vulnerabilities:** 1 vulnerability\n", "- **Vulnerabilities:** no known vulnerabilities\n"} {
		if !strings.Contains(complete, want) {
			t.Errorf("complete: lacks %q:\n%s", want, complete)
		}
	}
}

func TestInjectionIsEscaped(t *testing.T) {
	got := Markdown(injection())
	for _, raw := range injectionStrings {
		if strings.Contains(got, raw) {
			t.Errorf("raw vendor string %q survives in the Markdown:\n%s", raw, got)
		}
	}
	// Fragments that would still be live Markdown or HTML if they survived.
	for _, raw := range []string{"<script", "<img", "<iframe", "</", "[click me](", "**bold**", "_em_", "~~strike~~", "`code`", "&amp; <b>", "\n# Injected", "| cell |"} {
		if strings.Contains(got, raw) {
			t.Errorf("fragment %q survives in the Markdown:\n%s", raw, got)
		}
	}
	// The escaped forms the renderer must produce instead.
	for _, want := range []string{"&lt;script&gt;alert('xss')&lt;/script&gt;", `\[click me\](javascript:alert(1))`, `\*\*bold\*\* \_em\_ \~\~strike\~\~`, "\\`code\\` \\\\escape", `\| cell \| &lt;img src=x onerror=alert(1)&gt;`, "&amp;lt;b&amp;gt;entity&amp;lt;/b&amp;gt; &amp;amp; &lt;b&gt;tag&lt;/b&gt;", " # Injected heading  &lt;iframe"} {
		if !strings.Contains(got, want) {
			t.Errorf("escaped form %q missing from the Markdown:\n%s", want, got)
		}
	}
	// Only the renderer's own blocks may start a line; a vendor string
	// must never get to open a heading, quote or HTML block.
	for _, line := range strings.Split(got, "\n") {
		if strings.HasPrefix(line, "<") || strings.HasPrefix(line, "# Injected") {
			t.Errorf("vendor content starts a line: %q", line)
		}
	}
}

func TestEscape(t *testing.T) {
	for _, tt := range []struct{ in, want string }{
		{"plain 1.12.4", "plain 1.12.4"},
		{"<b>&</b>", "&lt;b&gt;&amp;&lt;/b&gt;"},
		{"*a* _b_ `c` ~d~ [e](f) g|h i\\j", `\*a\* \_b\_ \` + "`c\\`" + ` \~d\~ \[e\](f) g\|h i\\j`},
		{"line\r\nbreak\ttab\x00nul\u2028sep", "line  break tab nul sep"},
		{"&amp;", "&amp;amp;"},
		{"", ""},
	} {
		if got := escape(tt.in); got != tt.want {
			t.Errorf("escape(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestMarkdownIsStable(t *testing.T) {
	r := fixtures["complete"]()
	var a, b bytes.Buffer
	if err := WriteMarkdown(&a, r); err != nil {
		t.Fatal(err)
	}
	if err := WriteMarkdown(&b, r); err != nil {
		t.Fatal(err)
	}
	if a.String() != b.String() {
		t.Error("two renderings of the same report differ")
	}
}
