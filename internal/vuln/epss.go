package vuln

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// DefaultEPSSURL is FIRST's EPSS API.
const DefaultEPSSURL = "https://api.first.org"

// epssBatch is how many CVEs one EPSS request asks for; it is the API's
// default page size, so one page always holds the whole answer.
const epssBatch = 100

const maxEPSSResponseBytes = 2 << 20

// EPSS is the vuln.Enricher that adds FIRST's exploit prediction score to
// each finding with a CVE id.
type EPSS struct {
	BaseURL string
	Client  *http.Client
}

// NewEPSS returns an EPSS enricher for the public API with a 10 s timeout
// per request.
func NewEPSS() *EPSS {
	return &EPSS{BaseURL: DefaultEPSSURL, Client: &http.Client{Timeout: 10 * time.Second}}
}

var _ Enricher = (*EPSS)(nil)

func (e *EPSS) Name() string { return "EPSS" }

// epssResponse is the wire shape of GET /data/v1/epss. The API sends the
// score as a decimal string.
type epssResponse struct {
	Data []struct {
		CVE  string `json:"cve"`
		EPSS string `json:"epss"`
	} `json:"data"`
}

// Enrich returns the EPSS score of each CVE id that has one. Ids that are
// not CVEs (an OSV or GHSA id with no CVE alias) are never sent.
func (e *EPSS) Enrich(ctx context.Context, findingIDs []string) (map[string]Enrichment, error) {
	var cves []string
	for _, id := range findingIDs {
		if strings.HasPrefix(id, "CVE-") {
			cves = append(cves, id)
		}
	}
	out := map[string]Enrichment{}
	for start := 0; start < len(cves); start += epssBatch {
		batch := cves[start:min(start+epssBatch, len(cves))]
		v := url.Values{"cve": {strings.Join(batch, ",")}}
		var resp epssResponse
		if err := getJSON(ctx, e.Client, "epss", e.BaseURL+"/data/v1/epss?"+v.Encode(), nil, maxEPSSResponseBytes, &resp); err != nil {
			return nil, err
		}
		for _, d := range resp.Data {
			if d.CVE == "" {
				return nil, errors.New("epss: result without a cve")
			}
			score, err := strconv.ParseFloat(d.EPSS, 64)
			if err != nil || score < 0 || score > 1 {
				return nil, fmt.Errorf("epss: %s: bad score %q", d.CVE, d.EPSS)
			}
			out[d.CVE] = Enrichment{EPSS: &score}
		}
	}
	return out, nil
}
