package vuln

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// DefaultEPSSURL is the FIRST EPSS API.
const DefaultEPSSURL = "https://api.first.org/data/v1/epss"

// epssBatch is how many CVE ids one EPSS request asks for.
const epssBatch = 100

// EPSS is the Enricher that attaches the FIRST EPSS score (the probability of
// exploitation within 30 days) to each CVE it knows. A CVE EPSS does not
// score gets no entry, so its finding ranks after every scored one.
type EPSS struct {
	BaseURL string
	Client  *http.Client
}

// NewEPSS returns an EPSS enricher for the public API.
func NewEPSS() *EPSS {
	return &EPSS{BaseURL: DefaultEPSSURL, Client: &http.Client{Timeout: defaultFeedTimeout}}
}

var _ Enricher = (*EPSS)(nil)

func (e *EPSS) Name() string { return "FIRST EPSS" }

// epssResponse is the wire shape of GET /data/v1/epss. Scores come as strings.
type epssResponse struct {
	Status string `json:"status"`
	Data   []struct {
		CVE  string `json:"cve"`
		EPSS string `json:"epss"`
	} `json:"data"`
}

// Enrich asks EPSS for the CVE ids, one request per epssBatch ids. A failed
// request is an error for the whole call.
func (e *EPSS) Enrich(ctx context.Context, findingIDs []string) (map[string]Enrichment, error) {
	cves := cveIDs(findingIDs)
	out := map[string]Enrichment{}
	for start := 0; start < len(cves); start += epssBatch {
		batch := cves[start:min(start+epssBatch, len(cves))]
		q := url.Values{"cve": {strings.Join(batch, ",")}}
		var resp epssResponse
		if err := getJSON(ctx, e.Client, e.BaseURL+"?"+q.Encode(), nil, &resp); err != nil {
			return nil, fmt.Errorf("epss: %w", err)
		}
		if resp.Status != "OK" {
			return nil, fmt.Errorf("epss: status %q", resp.Status)
		}
		for _, d := range resp.Data {
			score, err := strconv.ParseFloat(d.EPSS, 64)
			if err != nil {
				return nil, fmt.Errorf("epss: %s: score %q: %w", d.CVE, d.EPSS, err)
			}
			out[d.CVE] = Enrichment{EPSS: &score}
		}
	}
	return out, nil
}
