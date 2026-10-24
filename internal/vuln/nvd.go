package vuln

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
)

// DefaultNVDURL is the NIST NVD 2.0 API.
const DefaultNVDURL = "https://services.nvd.nist.gov"

// nvdPageSize is the largest page NVD serves. A CPE with more matches than
// one page is reported as an error rather than read as complete.
const nvdPageSize = 2000

// NVDMaxLookups is how many CPE lookups one scan may make. NVD allows about
// 5 requests per 30 s without an API key and 50 per 30 s with one. Lookups
// past the cap are not made, and the scan reports them as incomplete.
func NVDMaxLookups(apiKey string) int {
	if apiKey == "" {
		return 5
	}
	return 50
}

// NVD is the vuln.Source that asks NIST NVD 2.0 for vulnerabilities by CPE.
// It is used for components that have no purl, so OSV cannot answer for
// them. Like OSV it calls with its own client, outside the vendor budget.
type NVD struct {
	BaseURL string
	Client  *http.Client
	// APIKey is sent in the apiKey header when set, which raises NVD's rate
	// limit. It is never put in a URL, a report or an error message.
	APIKey string
}

// NewNVD returns an NVD source for the public API. apiKey may be empty.
func NewNVD(apiKey string) *NVD {
	return &NVD{BaseURL: DefaultNVDURL, Client: &http.Client{Timeout: defaultFeedTimeout}, APIKey: apiKey}
}

var _ Source = (*NVD)(nil)

func (n *NVD) Name() string { return "NVD" }

// nvdResponse is the wire shape of GET /rest/json/cves/2.0. Only the fields
// Touchstone reads are declared.
type nvdResponse struct {
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE nvdCVE `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdCVE struct {
	ID           string `json:"id"`
	VulnStatus   string `json:"vulnStatus"`
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
	Type     string `json:"type"`
	CVSSData struct {
		BaseScore float64 `json:"baseScore"`
	} `json:"cvssData"`
}

// Lookup returns the CVEs NVD matches to each query's CPE. Queries without a
// CPE are ignored, and each CPE costs one request. A CVE NVD has rejected is
// dropped.
func (n *NVD) Lookup(ctx context.Context, queries []Query) ([]Finding, error) {
	var out []Finding
	for _, q := range queries {
		if q.CPE == "" {
			continue
		}
		findings, err := n.lookupCPE(ctx, q.CPE)
		if err != nil {
			return nil, err
		}
		out = append(out, findings...)
	}
	return out, nil
}

func (n *NVD) lookupCPE(ctx context.Context, cpe string) ([]Finding, error) {
	q := url.Values{"cpeName": {cpe}, "resultsPerPage": {strconv.Itoa(nvdPageSize)}}
	var page nvdResponse
	if err := getJSON(ctx, n.Client, n.BaseURL+"/rest/json/cves/2.0?"+q.Encode(), n.header(), &page); err != nil {
		return nil, fmt.Errorf("nvd: cpe %s: %w", cpe, err)
	}
	if page.TotalResults > len(page.Vulnerabilities) {
		return nil, fmt.Errorf("nvd: cpe %s: %d results, only %d returned", cpe, page.TotalResults, len(page.Vulnerabilities))
	}
	var out []Finding
	for _, v := range page.Vulnerabilities {
		if v.CVE.ID == "" {
			return nil, fmt.Errorf("nvd: cpe %s: result without a CVE id", cpe)
		}
		if v.CVE.VulnStatus == "Rejected" {
			continue
		}
		out = append(out, Finding{
			ID:       v.CVE.ID,
			Summary:  englishDescription(v.CVE),
			CVSSBase: cvssBase(v.CVE.Metrics.V31, v.CVE.Metrics.V30, v.CVE.Metrics.V2),
		})
	}
	return out, nil
}

// header carries the API key, if there is one.
func (n *NVD) header() http.Header {
	h := http.Header{}
	if n.APIKey != "" {
		h.Set("apiKey", n.APIKey)
	}
	return h
}

// englishDescription returns the English description, or "" if NVD has none.
func englishDescription(c nvdCVE) string {
	for _, d := range c.Descriptions {
		if d.Lang == "en" {
			return d.Value
		}
	}
	return ""
}

// cvssBase picks one base score: NVD's Primary metric from the newest CVSS
// version that has one, else the first metric of that version. nil if NVD
// has no score.
func cvssBase(lists ...[]nvdMetric) *float64 {
	for _, list := range lists {
		if len(list) == 0 {
			continue
		}
		pick := list[0]
		for _, m := range list {
			if m.Type == "Primary" {
				pick = m
				break
			}
		}
		score := pick.CVSSData.BaseScore
		return &score
	}
	return nil
}
