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
	"github.com/FootprintAI/touchstone/internal/pipeline"
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

// recordedFeeds replays the NVD, KEV and EPSS responses recorded under
// internal/vuln/testdata. NVD answers only the nginx CPE; anything else is a
// 404, which the scanner must report as a failed lookup.
func recordedFeeds(t *testing.T) *httptest.Server {
	t.Helper()
	dir := filepath.Join("..", "vuln", "testdata")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var file string
		switch {
		case r.URL.Path == "/rest/json/cves/2.0" && strings.Contains(r.URL.Query().Get("cpeName"), ":f5:nginx:"):
			file = "nvd/cpe-nginx-1.18.0.json"
		case r.URL.Path == "/kev.json":
			file = "kev/known_exploited_vulnerabilities.json"
		case r.URL.Path == "/data/v1/epss":
			file = "epss/epss.json"
		default:
			http.NotFound(w, r)
			return
		}
		b, err := os.ReadFile(filepath.Join(dir, file))
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

// newTestScanner wires every source to a recorded server: OSV at osvURL, and
// NVD, KEV and EPSS at the recorded feeds.
func newTestScanner(t *testing.T, osvURL string) *Scanner {
	t.Helper()
	feeds := recordedFeeds(t).URL
	return &Scanner{
		Fetch:  fetch.Options{AllowPrivate: true, Version: ToolVersion},
		Vulns:  &vuln.OSV{BaseURL: osvURL, Client: http.DefaultClient},
		CPE:    &vuln.NVD{BaseURL: feeds, Client: http.DefaultClient},
		CPEMax: vuln.NVDMaxLookups(""),
		KEV:    &vuln.KEV{URL: feeds + "/kev.json", Client: http.DefaultClient},
		EPSS:   &vuln.EPSS{BaseURL: feeds + "/data/v1/epss", Client: http.DefaultClient},
	}
}

// sourceStatus returns the SourceStatus named source, or nil.
func sourceStatus(rep *touchstonev1.ScanReport, source string) *touchstonev1.SourceStatus {
	for _, s := range rep.GetSources() {
		if s.GetSource() == source {
			return s
		}
	}
	return nil
}

// component returns the component named name, or nil.
func component(rep *touchstonev1.ScanReport, name string) *touchstonev1.Component {
	for _, c := range rep.GetComponents() {
		if c.GetName() == name {
			return c
		}
	}
	return nil
}

func TestScannerReportsJQueryWithOSVIDs(t *testing.T) {
	site := vendorSite(t)
	rep, err := newTestScanner(t, recordedOSVSite(t).URL).Scan(context.Background(),
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
	rep, err := newTestScanner(t, recordedOSVSite(t).URL).Scan(context.Background(),
		&touchstonev1.ScanRequest{Url: site.URL + "/"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	checked := rep.GetChecked()
	if len(checked) != 2 {
		t.Fatalf("checked = %v, want the target and the script", checked)
	}
	want := []struct{ url, reason string }{
		{site.URL + "/", "TARGET"},
		{site.URL + "/js/jquery-1.12.4.min.js", "SUBRESOURCE"},
	}
	for i, w := range want {
		if checked[i].GetUrl() != w.url || checked[i].GetReason() != w.reason ||
			checked[i].GetResult() != touchstonev1.CheckedLocation_RESULT_FOUND {
			t.Errorf("checked[%d] = %v, want %s %s FOUND", i, checked[i], w.reason, w.url)
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
	rep, err := newTestScanner(t, recordedOSVSite(t).URL).Scan(context.Background(),
		&touchstonev1.ScanRequest{Url: site.URL + "/", RequestBudget: 1})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	checked := rep.GetChecked()
	if len(checked) != 2 || checked[1].GetResult() != touchstonev1.CheckedLocation_RESULT_REFUSED {
		t.Fatalf("checked = %v, want the script refused by the budget", checked)
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
	rep, err := newTestScanner(t, recordedOSVSite(t).URL).Scan(context.Background(),
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

// downServer answers every request with 503, a vulnerability source that is
// unavailable.
func downServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestScannerOSVDownIsPartialWhenNVDAnswers(t *testing.T) {
	site := vendorSite(t)
	rep, err := newTestScanner(t, downServer(t).URL).Scan(context.Background(),
		&touchstonev1.ScanRequest{Url: site.URL + "/"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if rep.GetLookupStatus() != touchstonev1.LookupStatus_LOOKUP_STATUS_PARTIAL {
		t.Errorf("lookup_status = %v, want PARTIAL: NVD answered the nginx CPE", rep.GetLookupStatus())
	}
	if jq := component(rep, "jquery"); len(jq.GetVulnerabilities()) != 0 {
		t.Errorf("jquery has vulnerabilities despite the failed OSV lookup: %v", jq.GetVulnerabilities())
	}
	if s := sourceStatus(rep, "OSV"); s == nil || s.GetOk() || s.GetError() == "" {
		t.Errorf("OSV source status = %v, want ok=false with an error", s)
	}
	if s := sourceStatus(rep, "NVD"); s == nil || !s.GetOk() {
		t.Errorf("NVD source status = %v, want ok=true", s)
	}
}

func TestScannerFailedWhenEveryQuestionFails(t *testing.T) {
	site := vendorSite(t)
	s := newTestScanner(t, downServer(t).URL)
	s.CPE = &vuln.NVD{BaseURL: downServer(t).URL, Client: http.DefaultClient}
	rep, err := s.Scan(context.Background(), &touchstonev1.ScanRequest{Url: site.URL + "/"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if rep.GetLookupStatus() != touchstonev1.LookupStatus_LOOKUP_STATUS_FAILED {
		t.Errorf("lookup_status = %v, want FAILED: OSV and NVD both failed", rep.GetLookupStatus())
	}
}

func TestScannerLooksUpCPEOnlyComponentsInNVD(t *testing.T) {
	site := vendorSite(t)
	rep, err := newTestScanner(t, recordedOSVSite(t).URL).Scan(context.Background(),
		&touchstonev1.ScanRequest{Url: site.URL + "/"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	nginx := component(rep, "nginx")
	if nginx == nil {
		t.Fatalf("no nginx component in %v", rep.GetComponents())
	}
	if nginx.GetPurl() != "" || nginx.GetCpe() != "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*" {
		t.Fatalf("nginx = purl %q cpe %q, want a CPE-only component", nginx.GetPurl(), nginx.GetCpe())
	}
	var ids []string
	for _, v := range nginx.GetVulnerabilities() {
		ids = append(ids, v.GetId())
	}
	if len(ids) != 2 || ids[0] != "CVE-2021-23017" || ids[1] != "CVE-2019-20372" {
		t.Errorf("nginx vulnerability ids = %v, want the two NVD CVEs", ids)
	}
	if s := sourceStatus(rep, "NVD"); s == nil || !s.GetOk() {
		t.Errorf("NVD source status = %v, want ok=true", s)
	}
	if rep.GetLookupStatus() != touchstonev1.LookupStatus_LOOKUP_STATUS_COMPLETE {
		t.Errorf("lookup_status = %v, want COMPLETE", rep.GetLookupStatus())
	}
}

func TestScannerRanksKEVFirstThenEPSS(t *testing.T) {
	site := vendorSite(t)
	rep, err := newTestScanner(t, recordedOSVSite(t).URL).Scan(context.Background(),
		&touchstonev1.ScanRequest{Url: site.URL + "/"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	// CVE-2020-11022 is KEV-listed in the fixture, so it ranks first even
	// though EPSS alone would not put it there. CVE-2019-11358 is not
	// KEV-listed and ranks second.
	jq := component(rep, "jquery").GetVulnerabilities()
	if len(jq) != 2 || jq[0].GetId() != "CVE-2020-11022" || !jq[0].GetKev() || jq[0].GetEpss() != 0.94321 {
		t.Errorf("jquery vulnerabilities = %v, want CVE-2020-11022 first with KEV and EPSS 0.94321", jq)
	}
	if jq[1].GetId() != "CVE-2019-11358" || jq[1].GetKev() || jq[1].GetEpss() != 0.01234 {
		t.Errorf("second jquery vulnerability = %v, want CVE-2019-11358 with EPSS 0.01234 and no KEV", jq[1])
	}
	// The nginx KEV entry ranks first, and the CVE EPSS does not score ranks
	// last, with its CVSS carried through.
	ng := component(rep, "nginx").GetVulnerabilities()
	if len(ng) != 2 || ng[0].GetId() != "CVE-2021-23017" || !ng[0].GetKev() || ng[0].GetCvssBase() != 7.7 {
		t.Errorf("nginx vulnerabilities = %v, want the KEV CVE first with CVSS 7.7", ng)
	}
	if ng[1].Epss != nil || ng[1].GetCvssBase() != 5.0 {
		t.Errorf("second nginx vulnerability = %v, want no EPSS and CVSS 5.0", ng[1])
	}
}

func TestScannerKEVFailureIsPartial(t *testing.T) {
	site := vendorSite(t)
	s := newTestScanner(t, recordedOSVSite(t).URL)
	s.KEV = &vuln.KEV{URL: downServer(t).URL + "/kev.json", Client: http.DefaultClient}
	rep, err := s.Scan(context.Background(), &touchstonev1.ScanRequest{Url: site.URL + "/"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if rep.GetLookupStatus() != touchstonev1.LookupStatus_LOOKUP_STATUS_PARTIAL {
		t.Errorf("lookup_status = %v, want PARTIAL: KEV could not be read", rep.GetLookupStatus())
	}
	if st := sourceStatus(rep, "CISA KEV"); st == nil || st.GetOk() || st.GetError() == "" {
		t.Errorf("CISA KEV source status = %v, want ok=false with an error", st)
	}
}

func TestScannerCapsCPELookupsAndReportsTheCap(t *testing.T) {
	s := newTestScanner(t, recordedOSVSite(t).URL)
	s.CPEMax = 1
	comps := []pipeline.Component{
		{Name: "nginx", Version: "1.18.0", CPE: "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*"},
		{Name: "nginx", Version: "1.17.0", CPE: "cpe:2.3:a:f5:nginx:1.17.0:*:*:*:*:*:*:*"},
	}
	rep := &touchstonev1.ScanReport{}
	status, out := s.lookup(context.Background(), rep, comps)

	if status != touchstonev1.LookupStatus_LOOKUP_STATUS_PARTIAL {
		t.Errorf("lookup_status = %v, want PARTIAL: the second CPE was not looked up", status)
	}
	if len(out) != 2 {
		t.Fatalf("components = %d, want both reported", len(out))
	}
	st := sourceStatus(rep, "NVD")
	if st == nil || st.GetOk() || !strings.Contains(st.GetError(), "capped at 1 CPE lookups per scan, 1 components not looked up") {
		t.Errorf("NVD source status = %v, want the cap reported", st)
	}
}

func TestScannerRejectsNonHTTPTarget(t *testing.T) {
	_, err := newTestScanner(t, "http://unused").Scan(context.Background(),
		&touchstonev1.ScanRequest{Url: "ftp://vendor.example/"})
	if err == nil {
		t.Fatal("Scan: want an InvalidArgument error for an ftp URL")
	}
}
