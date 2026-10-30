package vuln

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"
)

// DefaultKEVURL is CISA's Known Exploited Vulnerabilities catalog.
const DefaultKEVURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

// KEVTTL is how long a fetched KEV catalog is reused. The catalog is the
// only state Touchstone keeps between scans (see
// docs/architecture/touchstone.md).
const KEVTTL = 6 * time.Hour

// maxKEVResponseBytes caps the catalog download (about 1.5 MiB today).
const maxKEVResponseBytes = 32 << 20

// KEV is the vuln.Enricher that flags findings listed in CISA KEV. The
// feed is fetched on first use and cached in memory for KEVTTL; a KEV is
// safe for concurrent scans.
type KEV struct {
	URL    string
	Client *http.Client

	// Now returns the current time for the cache; time.Now if nil.
	Now func() time.Time

	mu        sync.Mutex
	cves      map[string]bool
	fetchedAt time.Time
}

// NewKEV returns a KEV enricher for CISA's feed with a 30 s timeout.
func NewKEV() *KEV {
	return &KEV{URL: DefaultKEVURL, Client: &http.Client{Timeout: 30 * time.Second}}
}

var _ Enricher = (*KEV)(nil)

func (k *KEV) Name() string { return "KEV" }

// kevCatalog is the wire shape of the KEV feed. Only the fields Touchstone
// reads are declared.
type kevCatalog struct {
	Vulnerabilities []struct {
		CVEID string `json:"cveID"`
	} `json:"vulnerabilities"`
}

// Enrich returns {KEV: true} for each id in the catalog; other ids are
// left out.
func (k *KEV) Enrich(ctx context.Context, findingIDs []string) (map[string]Enrichment, error) {
	cves, err := k.catalog(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string]Enrichment{}
	for _, id := range findingIDs {
		if cves[id] {
			out[id] = Enrichment{KEV: true}
		}
	}
	return out, nil
}

// catalog returns the cached CVE set, fetching it when it is missing or
// older than KEVTTL. A failed refresh is an error, not a stale answer.
func (k *KEV) catalog(ctx context.Context) (map[string]bool, error) {
	now := time.Now
	if k.Now != nil {
		now = k.Now
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.cves != nil && now().Sub(k.fetchedAt) < KEVTTL {
		return k.cves, nil
	}
	var c kevCatalog
	if err := getJSON(ctx, k.Client, "kev", k.URL, nil, maxKEVResponseBytes, &c); err != nil {
		return nil, err
	}
	if len(c.Vulnerabilities) == 0 {
		return nil, errors.New("kev: catalog lists no vulnerabilities")
	}
	cves := make(map[string]bool, len(c.Vulnerabilities))
	for _, v := range c.Vulnerabilities {
		if v.CVEID == "" {
			return nil, errors.New("kev: catalog entry without a cveID")
		}
		cves[v.CVEID] = true
	}
	k.cves, k.fetchedAt = cves, now()
	return cves, nil
}
