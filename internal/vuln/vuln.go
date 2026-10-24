// Package vuln defines the Source and Enricher seams used to look up and
// enrich vulnerabilities for a component, their implementations (OSV by
// purl, NVD by CPE, KEV and EPSS enrichment) and the pure ranking step. See
// docs/architecture/touchstone.md.
package vuln

import (
	"context"
	"sort"
)

// Query identifies a component to look up. At least one of Purl or CPE is
// set; Source implementations that only support one kind ignore queries
// missing it.
type Query struct {
	Purl string
	CPE  string
}

// Finding is one vulnerability returned by a Source. KEV and EPSS are set
// afterwards by an Enricher (see Apply); a Source leaves them zero.
type Finding struct {
	ID       string // CVE id when one exists, else the source's native id
	Aliases  []string
	Summary  string
	CVSSBase *float64
	KEV      bool     // listed in CISA's Known Exploited Vulnerabilities catalog
	EPSS     *float64 // FIRST EPSS probability; nil when there is no score
}

// Source looks up vulnerabilities for a batch of components. Each
// implementation (OSV, NVD) reports its own name so pipeline can record a
// per-source SourceStatus.
type Source interface {
	Name() string
	Lookup(ctx context.Context, queries []Query) ([]Finding, error)
}

// Enrichment is additional data an Enricher attaches to a Finding by id.
type Enrichment struct {
	KEV  bool
	EPSS *float64
}

// Enricher adds data to findings already produced by a Source (KEV, EPSS).
// It never removes or invents findings.
type Enricher interface {
	Name() string
	Enrich(ctx context.Context, findingIDs []string) (map[string]Enrichment, error)
}

// Apply copies enrichments onto findings by id. A field an enrichment leaves
// unset is not cleared, so the KEV and EPSS results can be applied one after
// the other.
func Apply(findings []Finding, enrichments ...map[string]Enrichment) {
	for i := range findings {
		for _, m := range enrichments {
			e, ok := m[findings[i].ID]
			if !ok {
				continue
			}
			if e.KEV {
				findings[i].KEV = true
			}
			if e.EPSS != nil {
				findings[i].EPSS = e.EPSS
			}
		}
	}
}

// Rank orders findings in place for the report: KEV-listed first, then EPSS
// descending, then CVSS base score descending. A missing EPSS sorts after
// every present one, and a missing CVSS after every present one. Ties fall
// back to the id, so the order is deterministic.
func Rank(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.KEV != b.KEV {
			return a.KEV
		}
		if c := compareDesc(a.EPSS, b.EPSS); c != 0 {
			return c < 0
		}
		if c := compareDesc(a.CVSSBase, b.CVSSBase); c != 0 {
			return c < 0
		}
		return a.ID < b.ID
	})
}

// compareDesc orders optional scores largest first with nil last. It returns
// a negative number when a comes before b.
func compareDesc(a, b *float64) int {
	switch {
	case a == nil && b == nil:
		return 0
	case a == nil:
		return 1
	case b == nil:
		return -1
	case *a > *b:
		return -1
	case *a < *b:
		return 1
	default:
		return 0
	}
}
