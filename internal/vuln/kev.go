package vuln

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// DefaultKEVURL is CISA's Known Exploited Vulnerabilities catalog.
const DefaultKEVURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

// KEVTTL is how long the catalog is reused before it is fetched again.
const KEVTTL = 6 * time.Hour

// KEV is the Enricher that flags CVEs listed in CISA's KEV catalog. The
// catalog is held in memory for KEVTTL, so a process fetches it at most once
// per TTL however many scans it runs.
type KEV struct {
	URL    string
	Client *http.Client
	TTL    time.Duration // KEVTTL if zero
	Now    func() time.Time

	mu      sync.Mutex
	listed  map[string]bool
	fetched time.Time
}

// NewKEV returns a KEV enricher for the public catalog.
func NewKEV() *KEV {
	return &KEV{URL: DefaultKEVURL, Client: &http.Client{Timeout: defaultFeedTimeout}}
}

var _ Enricher = (*KEV)(nil)

func (k *KEV) Name() string { return "CISA KEV" }

// kevFeed is the wire shape of the catalog. Only the CVE ids are read.
type kevFeed struct {
	Vulnerabilities []struct {
		CVEID string `json:"cveID"`
	} `json:"vulnerabilities"`
}

// Enrich sets KEV on the CVE ids the catalog lists. It fetches the catalog
// only when there is a CVE id to check, and a failed fetch is an error, so
// an unreadable catalog is never read as "not listed".
func (k *KEV) Enrich(ctx context.Context, findingIDs []string) (map[string]Enrichment, error) {
	cves := cveIDs(findingIDs)
	out := map[string]Enrichment{}
	if len(cves) == 0 {
		return out, nil
	}
	listed, err := k.catalog(ctx)
	if err != nil {
		return nil, err
	}
	for _, id := range cves {
		if listed[id] {
			out[id] = Enrichment{KEV: true}
		}
	}
	return out, nil
}

// catalog returns the set of listed CVE ids, from memory while it is fresh.
func (k *KEV) catalog(ctx context.Context) (map[string]bool, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	now := time.Now
	if k.Now != nil {
		now = k.Now
	}
	ttl := KEVTTL
	if k.TTL != 0 {
		ttl = k.TTL
	}
	at := now()
	if k.listed != nil && at.Sub(k.fetched) < ttl {
		return k.listed, nil
	}

	var feed kevFeed
	if err := getJSON(ctx, k.Client, k.URL, nil, &feed); err != nil {
		return nil, fmt.Errorf("kev: %w", err)
	}
	if len(feed.Vulnerabilities) == 0 {
		return nil, errors.New("kev: catalog lists no vulnerabilities")
	}
	listed := make(map[string]bool, len(feed.Vulnerabilities))
	for _, v := range feed.Vulnerabilities {
		if v.CVEID == "" {
			return nil, errors.New("kev: catalog entry without cveID")
		}
		listed[v.CVEID] = true
	}
	k.listed, k.fetched = listed, at
	return listed, nil
}
