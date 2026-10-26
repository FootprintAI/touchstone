package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	touchstonev1 "github.com/FootprintAI/touchstone/gen/go/touchstone/v1"
	"github.com/FootprintAI/touchstone/internal/fetch"
	"github.com/FootprintAI/touchstone/internal/vuln"
)

const fixturePage = `<!doctype html><html><head>
<script src="/js/jquery-1.12.4.min.js"></script>
</head><body>vendor</body></html>`

// vendorSite serves the fixture page and its jQuery script. The page is
// served with a Server banner so the header rule is exercised too.
func vendorSite(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Server", "nginx/1.18.0")
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(fixturePage))
	})
	mux.HandleFunc("/js/jquery-1.12.4.min.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte("/*! jQuery v1.12.4 */"))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// recordedOSVSite replays the OSV responses recorded in internal/vuln.
func recordedOSVSite(t *testing.T) *httptest.Server {
	t.Helper()
	dir := filepath.Join("..", "vuln", "testdata", "osv")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var file string
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/querybatch":
			file = filepath.Join(dir, "querybatch-jquery-1.12.4.json")
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/vulns/"):
			file = filepath.Join(dir, "vulns", strings.TrimPrefix(r.URL.Path, "/v1/vulns/")+".json")
		default:
			http.NotFound(w, r)
			return
		}
		b, err := os.ReadFile(file)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newTestScanner(osvURL string) *Scanner {
	return &Scanner{
		Fetch: fetch.Options{AllowPrivate: true, Version: ToolVersion},
		Vulns: &vuln.OSV{BaseURL: osvURL, Client: http.DefaultClient},
	}
}

func TestScannerReportsJQueryWithOSVIDs(t *testing.T) {
	site := vendorSite(t)
	rep, err := newTestScanner(recordedOSVSite(t).URL).Scan(context.Background(),
		&touchstonev1.ScanRequest{Url: site.URL + "/"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if rep.GetScanStatus() != touchstonev1.ScanStatus_SCAN_STATUS_OK {
		t.Fatalf("scan_status = %v, want OK", rep.GetScanStatus())
	}
	if rep.GetLookupStatus() != touchstonev1.LookupStatus_LOOKUP_STATUS_COMPLETE {
		t.Errorf("lookup_status = %v, want COMPLETE", rep.GetLookupStatus())
	}
	if len(rep.GetComponents()) != 2 {
		t.Fatalf("components = %v, want jquery and the nginx banner", rep.GetComponents())
	}

	var jq *touchstonev1.Component
	for _, c := range rep.GetComponents() {
		if c.GetName() == "jquery" {
			jq = c
		}
	}
	if jq == nil {
		t.Fatalf("no jquery component in %v", rep.GetComponents())
	}
	if jq.GetVersion() != "1.12.4" || jq.GetPurl() != "pkg:npm/jquery@1.12.4" {
		t.Errorf("jquery = version %q purl %q", jq.GetVersion(), jq.GetPurl())
	}
	if jq.GetConfidence() != touchstonev1.Confidence_CONFIDENCE_LOW {
		t.Errorf("confidence = %v, want LOW", jq.GetConfidence())
	}
	if len(jq.GetEvidence()) != 1 || jq.GetEvidence()[0].GetLocation() != site.URL+"/js/jquery-1.12.4.min.js" ||
		jq.GetEvidence()[0].GetKind() != touchstonev1.EvidenceKind_EVIDENCE_KIND_FINGERPRINT_ASSET {
		t.Errorf("evidence = %v, want the script URL as asset evidence", jq.GetEvidence())
	}
	var ids []string
	for _, v := range jq.GetVulnerabilities() {
		ids = append(ids, v.GetId())
	}
	if !contains(ids, "CVE-2020-11022") {
		t.Errorf("vulnerability ids = %v, want CVE-2020-11022", ids)
	}
}

func TestScannerCheckedListMatchesRequests(t *testing.T) {
	site := vendorSite(t)
	rep, err := newTestScanner(recordedOSVSite(t).URL).Scan(context.Background(),
		&touchstonev1.ScanRequest{Url: site.URL + "/"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	checked := rep.GetChecked()
	if len(checked) != 6 {
		t.Fatalf("checked = %v, want the target, the script and the four discovery paths", checked)
	}
	want := []struct {
		url, reason string
		result      touchstonev1.CheckedLocation_Result
	}{
		{site.URL + "/", "TARGET", touchstonev1.CheckedLocation_RESULT_FOUND},
		{site.URL + "/js/jquery-1.12.4.min.js", "SUBRESOURCE", touchstonev1.CheckedLocation_RESULT_FOUND},
		{site.URL + "/.well-known/security.txt", "DISCOVERY_PATH", touchstonev1.CheckedLocation_RESULT_NOT_FOUND},
		{site.URL + "/security.txt", "DISCOVERY_PATH", touchstonev1.CheckedLocation_RESULT_NOT_FOUND},
		{site.URL + "/.well-known/csaf/provider-metadata.json", "DISCOVERY_PATH", touchstonev1.CheckedLocation_RESULT_NOT_FOUND},
		{site.URL + "/.well-known/tea", "DISCOVERY_PATH", touchstonev1.CheckedLocation_RESULT_NOT_FOUND},
	}
	for i, w := range want {
		if checked[i].GetUrl() != w.url || checked[i].GetReason() != w.reason || checked[i].GetResult() != w.result {
			t.Errorf("checked[%d] = %v, want %s %s %v", i, checked[i], w.reason, w.url, w.result)
		}
	}
	if rep.GetRequestsUsed() != uint32(len(checked)) {
		t.Errorf("requests_used = %d, want %d", rep.GetRequestsUsed(), len(checked))
	}
	if rep.GetRequestBudget() != fetch.DefaultBudget {
		t.Errorf("request_budget = %d, want %d", rep.GetRequestBudget(), fetch.DefaultBudget)
	}
}

func TestScannerRecordsScriptRefusedByBudget(t *testing.T) {
	site := vendorSite(t)
	rep, err := newTestScanner(recordedOSVSite(t).URL).Scan(context.Background(),
		&touchstonev1.ScanRequest{Url: site.URL + "/", RequestBudget: 1})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	checked := rep.GetChecked()
	if len(checked) < 2 || checked[1].GetResult() != touchstonev1.CheckedLocation_RESULT_REFUSED {
		t.Fatalf("checked = %v, want the script refused by the budget", checked)
	}
	for _, c := range checked[1:] {
		if c.GetResult() != touchstonev1.CheckedLocation_RESULT_REFUSED {
			t.Errorf("%v: want every request after the target refused by the budget", c)
		}
	}
	if rep.GetRequestsUsed() != 1 {
		t.Errorf("requests_used = %d, want 1", rep.GetRequestsUsed())
	}
	if len(rep.GetComponents()) != 1 || rep.GetComponents()[0].GetName() != "nginx" {
		t.Errorf("components = %v, want only the banner (the script was never loaded)", rep.GetComponents())
	}
}

func TestScannerTargetUnreachable(t *testing.T) {
	site := httptest.NewServer(http.NotFoundHandler())
	site.Close()
	rep, err := newTestScanner(recordedOSVSite(t).URL).Scan(context.Background(),
		&touchstonev1.ScanRequest{Url: site.URL + "/"})
	if err != nil {
		t.Fatalf("Scan: an unreachable target is a report, not an RPC error: %v", err)
	}
	if rep.GetScanStatus() != touchstonev1.ScanStatus_SCAN_STATUS_TARGET_UNREACHABLE {
		t.Errorf("scan_status = %v, want TARGET_UNREACHABLE", rep.GetScanStatus())
	}
	if len(rep.GetComponents()) != 0 || rep.GetLookupStatus() != touchstonev1.LookupStatus_LOOKUP_STATUS_UNSPECIFIED {
		t.Errorf("report carries components or a lookup status: %v", rep)
	}
	if len(rep.GetChecked()) != 1 || rep.GetRequestsUsed() != 1 {
		t.Errorf("checked = %v, requests_used = %d; want the one attempt", rep.GetChecked(), rep.GetRequestsUsed())
	}
}

func TestScannerOSVDownIsFailedLookup(t *testing.T) {
	osv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	t.Cleanup(osv.Close)
	site := vendorSite(t)
	rep, err := newTestScanner(osv.URL).Scan(context.Background(),
		&touchstonev1.ScanRequest{Url: site.URL + "/"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if rep.GetLookupStatus() != touchstonev1.LookupStatus_LOOKUP_STATUS_FAILED {
		t.Errorf("lookup_status = %v, want FAILED", rep.GetLookupStatus())
	}
	for _, c := range rep.GetComponents() {
		if len(c.GetVulnerabilities()) != 0 {
			t.Errorf("component %s has vulnerabilities despite the failed lookup", c.GetName())
		}
	}
	var osvStatus *touchstonev1.SourceStatus
	for _, s := range rep.GetSources() {
		if s.GetSource() == "OSV" {
			osvStatus = s
		}
	}
	if osvStatus == nil || osvStatus.GetOk() || osvStatus.GetError() == "" {
		t.Errorf("OSV source status = %v, want ok=false with an error", osvStatus)
	}
}

func TestScannerRejectsNonHTTPTarget(t *testing.T) {
	_, err := newTestScanner("http://unused").Scan(context.Background(),
		&touchstonev1.ScanRequest{Url: "ftp://vendor.example/"})
	if err == nil {
		t.Fatal("Scan: want an InvalidArgument error for an ftp URL")
	}
}
