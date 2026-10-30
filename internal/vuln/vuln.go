// Package vuln looks up and enriches vulnerabilities for components: the
// Source seam (OSV by purl, NVD by CPE), the Enricher seam (KEV, EPSS),
// Rank, and the Matcher that combines them and decides the lookup status
// (see docs/architecture/touchstone.md).
package vuln

import "context"

// Query identifies a component to look up. At least one of Purl or CPE is
// set; Source implementations that only support one kind ignore queries
// missing it.
type Query struct {
	Purl string
	CPE  string
}

// Finding is one vulnerability returned by a Source, before enrichment.
type Finding struct {
	ID       string // CVE id when one exists, else the source's native id
	Aliases  []string
	Summary  string
	CVSSBase *float64
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
