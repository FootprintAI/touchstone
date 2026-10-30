package vuln

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// DefaultNVDURL is the public NVD API.
const DefaultNVDURL = "https://services.nvd.nist.gov"

// UnauthenticatedNVDLimit is how many CPE lookups one scan makes without
// NVD_API_KEY. NVD allows about 5 unauthenticated requests per 30 s.
const UnauthenticatedNVDLimit = 5

// maxNVDResponseBytes caps one NVD response; a popular CPE can match a
// few hundred CVEs.
const maxNVDResponseBytes = 16 << 20

// nvdPageSize is the most results NVD returns in one page.
const nvdPageSize = 2000

// NVD is the vuln.Source that asks NVD 2.0 for the CVEs that apply to a
// CPE. It is used for components that have no purl. Like OSV, it calls
// the API with its own client, outside the vendor's request budget.
type NVD struct {
	BaseURL string
	APIKey  string // optional; sent as the apiKey header
	Client  *http.Client
}

// NewNVD returns an NVD source for the public API with a 20 s timeout per
// request. apiKey may be empty.
func NewNVD(apiKey string) *NVD {
	return &NVD{BaseURL: DefaultNVDURL, APIKey: apiKey, Client: &http.Client{Timeout: 20 * time.Second}}
}

var _ Source = (*NVD)(nil)

func (n *NVD) Name() string { return "NVD" }

// PerScanLimit is how many CPE lookups a scan may make: 0 (no cap) with an
// API key, UnauthenticatedNVDLimit without one.
func (n *NVD) PerScanLimit() int {
	if n.APIKey != "" {
		return 0
	}
	return UnauthenticatedNVDLimit
}

// nvdResponse is the wire shape of GET /rest/json/cves/2.0. Only the
// fields Touchstone reads are declared.
type nvdResponse struct {
	TotalResults    *int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE nvdCVE `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdCVE struct {
	ID           string `json:"id"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics struct {
		V31 []nvdMetric `json:"cvssMetricV31"`
		V30 []nvdMetric `json:"cvssMetricV30"`
		V2  []nvdMetric `json:"cvssMetricV2"`
	} `json:"metrics"`
}

type nvdMetric struct {
	Type     string `json:"type"` // Primary or Secondary
	CVSSData struct {
		BaseScore *float64 `json:"baseScore"`
	} `json:"cvssData"`
}

// Lookup returns the CVEs for every query that carries a CPE and no purl
// (purl queries are OSV's). Each CPE is one request.
func (n *NVD) Lookup(ctx context.Context, queries []Query) ([]Finding, error) {
	var header http.Header
	if n.APIKey != "" {
		header = http.Header{"apiKey": {n.APIKey}}
	}
	var out []Finding
	seen := map[string]bool{}
	for _, q := range queries {
		if q.CPE == "" || q.Purl != "" {
			continue
		}
		v := url.Values{"cpeName": {q.CPE}, "resultsPerPage": {fmt.Sprint(nvdPageSize)}}
		var resp nvdResponse
		if err := getJSON(ctx, n.Client, "nvd", n.BaseURL+"/rest/json/cves/2.0?"+v.Encode(), header, maxNVDResponseBytes, &resp); err != nil {
			return nil, err
		}
		if resp.TotalResults == nil {
			return nil, fmt.Errorf("nvd: %s: response has no totalResults", q.CPE)
		}
		if *resp.TotalResults > len(resp.Vulnerabilities) {
			return nil, fmt.Errorf("nvd: %s: %d results, only %d returned", q.CPE, *resp.TotalResults, len(resp.Vulnerabilities))
		}
		for _, r := range resp.Vulnerabilities {
			if r.CVE.ID == "" {
				return nil, fmt.Errorf("nvd: %s: result without a CVE id", q.CPE)
			}
			if !seen[r.CVE.ID] {
				seen[r.CVE.ID] = true
				out = append(out, findingFromNVD(r.CVE))
			}
		}
	}
	return out, nil
}

// findingFromNVD takes the English description as the summary and the
// newest CVSS version's base score, preferring NVD's own (Primary) metric.
func findingFromNVD(c nvdCVE) Finding {
	f := Finding{ID: c.ID}
	for _, d := range c.Descriptions {
		if d.Lang == "en" {
			f.Summary = d.Value
			break
		}
	}
	for _, metrics := range [][]nvdMetric{c.Metrics.V31, c.Metrics.V30, c.Metrics.V2} {
		if s := baseScore(metrics); s != nil {
			f.CVSSBase = s
			break
		}
	}
	return f
}

func baseScore(metrics []nvdMetric) *float64 {
	for _, m := range metrics {
		if m.Type == "Primary" && m.CVSSData.BaseScore != nil {
			return m.CVSSData.BaseScore
		}
	}
	for _, m := range metrics {
		if m.CVSSData.BaseScore != nil {
			return m.CVSSData.BaseScore
		}
	}
	return nil
}
