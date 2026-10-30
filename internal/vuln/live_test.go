//go:build live

// The live smoke test asks the real OSV, NVD, KEV and EPSS services. It is
// opt-in (go test -tags live ./internal/vuln) and meant for the nightly
// job, never for pull requests. NVD_API_KEY is used when set.

package vuln

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestLiveMatch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	nvd := NewNVD(os.Getenv("NVD_API_KEY"))
	m := &Matcher{
		Purl:      NewOSV(),
		CPE:       nvd,
		CPELimit:  nvd.PerScanLimit(),
		Enrichers: []Enricher{NewKEV(), NewEPSS()},
	}
	res := m.Match(ctx, []Query{
		{Purl: "pkg:npm/jquery@1.12.4"},
		{CPE: "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*"},
		{Purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},
	})
	if res.Status != StatusComplete {
		t.Fatalf("Status = %v, want complete: %+v", res.Status, res.Sources)
	}
	for i, name := range []string{"jquery (OSV)", "nginx (NVD)", "log4j-core (OSV)"} {
		if len(res.Matches[i]) == 0 {
			t.Errorf("%s: no vulnerabilities", name)
		}
	}
	// Log4Shell is in KEV, so it ranks first for log4j-core and has a score.
	if len(res.Matches[2]) > 0 {
		top := res.Matches[2][0]
		if !top.KEV || top.EPSS == nil {
			t.Errorf("log4j-core top match = %+v, want a KEV-listed CVE with an EPSS score", top)
		}
	}
}
