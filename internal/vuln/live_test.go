//go:build live

package vuln

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestLiveNVDKEVEPSS calls the real NVD, CISA KEV and FIRST EPSS APIs with
// one component. It is opt-in (go test -tags live ./internal/vuln/) and runs
// nightly, never on pull requests. NVD_API_KEY is optional. The assertions
// are shape checks only, because the live data changes.
func TestLiveNVDKEVEPSS(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	findings, err := NewNVD(os.Getenv("NVD_API_KEY")).Lookup(ctx, []Query{{CPE: "cpe:2.3:a:jquery:jquery:1.12.4:*:*:*:*:*:*:*"}})
	if err != nil {
		t.Fatalf("NVD lookup: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("NVD returned no CVEs for jquery 1.12.4")
	}

	var ids []string
	for _, f := range findings {
		ids = append(ids, f.ID)
	}
	if _, err := NewKEV().Enrich(ctx, ids); err != nil {
		t.Fatalf("KEV enrich: %v", err)
	}
	epss, err := NewEPSS().Enrich(ctx, ids)
	if err != nil {
		t.Fatalf("EPSS enrich: %v", err)
	}
	if len(epss) == 0 {
		t.Errorf("EPSS scored none of %v", ids)
	}
}
